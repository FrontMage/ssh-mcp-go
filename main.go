package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/melbahja/goph"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type sshConfig struct {
	User string
	Host string
	Port uint
	Auth goph.Auth
}

type transferStats struct {
	Files int
	Dirs  int
	Bytes int64
}

func (s transferStats) String() string {
	return fmt.Sprintf("files=%d dirs=%d bytes=%d", s.Files, s.Dirs, s.Bytes)
}

func main() {
	s := server.NewMCPServer("ssh-mcp", "1.0.0")

	execTool := mcp.NewTool("ssh_exec",
		mcp.WithDescription("Execute a command on the configured SSH server and return the output"),
		mcp.WithString("command",
			mcp.Required(),
			mcp.Description("Command to run on the remote host"),
		),
	)

	uploadTool := mcp.NewTool("ssh_upload",
		mcp.WithDescription("Upload a local file or directory to the configured SSH server"),
		mcp.WithString("local_path",
			mcp.Required(),
			mcp.Description("Path to the local file or directory"),
		),
		mcp.WithString("remote_path",
			mcp.Required(),
			mcp.Description("Destination path on the remote host"),
		),
	)

	downloadTool := mcp.NewTool("ssh_download",
		mcp.WithDescription("Download a remote file or directory to the local machine"),
		mcp.WithString("remote_path",
			mcp.Required(),
			mcp.Description("Path to the remote file or directory"),
		),
		mcp.WithString("local_path",
			mcp.Required(),
			mcp.Description("Destination path on the local machine"),
		),
	)

	execDynamicTool := mcp.NewTool("ssh_exec_dynamic",
		mcp.WithDescription("Execute a command with dynamic SSH parameters (no env required)"),
		mcp.WithString("server",
			mcp.Required(),
			mcp.Description("SSH server in host or user@host format"),
		),
		mcp.WithString("user",
			mcp.Description("SSH username (required if server has no user@)"),
		),
		mcp.WithInt("port",
			mcp.Description("SSH port (default 22)"),
		),
		mcp.WithString("password",
			mcp.Description("SSH password"),
		),
		mcp.WithString("key_path",
			mcp.Description("Path to private key file"),
		),
		mcp.WithString("passphrase",
			mcp.Description("Private key passphrase"),
		),
		mcp.WithString("command",
			mcp.Required(),
			mcp.Description("Command to run on the remote host"),
		),
	)

	s.AddTool(execTool, execHandler)
	s.AddTool(uploadTool, uploadHandler)
	s.AddTool(downloadTool, downloadHandler)
	s.AddTool(execDynamicTool, execDynamicHandler)

	if err := server.ServeStdio(s); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}

func execHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	command, err := request.RequireString("command")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	client, err := newClient()
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	defer client.Close()

	output, err := client.Run(command)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("command failed: %v\n%s", err, string(output))), nil
	}

	return mcp.NewToolResultText(string(output)), nil
}

func uploadHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	localPath, err := request.RequireString("local_path")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	remotePath, err := request.RequireString("remote_path")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	client, err := newClient()
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	defer client.Close()

	stats, err := uploadPath(client, localPath, remotePath)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("upload complete: %s", stats.String())), nil
}

func downloadHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	remotePath, err := request.RequireString("remote_path")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	localPath, err := request.RequireString("local_path")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	client, err := newClient()
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	defer client.Close()

	stats, err := downloadPath(client, remotePath, localPath)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("download complete: %s", stats.String())), nil
}

func execDynamicHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	server, err := request.RequireString("server")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	command, err := request.RequireString("command")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	args := request.GetArguments()
	port := 22
	if _, ok := args["port"]; ok {
		portValue, err := request.RequireInt("port")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if portValue <= 0 || portValue > 65535 {
			return mcp.NewToolResultError(fmt.Sprintf("invalid port: %d", portValue)), nil
		}
		port = portValue
	}

	user, host := parseServer(server)
	if host == "" {
		return mcp.NewToolResultError("server is empty"), nil
	}
	if user == "" {
		user = request.GetString("user", "")
	}
	if user == "" {
		return mcp.NewToolResultError("user is required when server has no user@"), nil
	}

	password := request.GetString("password", "")
	keyPath := request.GetString("key_path", "")
	passphrase := request.GetString("passphrase", "")

	auth, err := authFromParams(keyPath, passphrase, password)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	client, err := goph.NewConn(&goph.Config{
		User:     user,
		Addr:     host,
		Port:     uint(port),
		Auth:     auth,
		Timeout:  goph.DefaultTimeout,
		Callback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("ssh connect: %v", err)), nil
	}
	defer client.Close()

	output, err := client.Run(command)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("command failed: %v\n%s", err, string(output))), nil
	}

	return mcp.NewToolResultText(string(output)), nil
}

func newClient() (*goph.Client, error) {
	cfg, err := loadSSHConfig()
	if err != nil {
		return nil, err
	}

	callback := ssh.InsecureIgnoreHostKey()

	client, err := goph.NewConn(&goph.Config{
		User:     cfg.User,
		Addr:     cfg.Host,
		Port:     cfg.Port,
		Auth:     cfg.Auth,
		Timeout:  goph.DefaultTimeout,
		Callback: callback,
	})
	if err != nil {
		return nil, fmt.Errorf("ssh connect: %w", err)
	}

	return client, nil
}

func loadSSHConfig() (*sshConfig, error) {
	server := strings.TrimSpace(os.Getenv("SSH_SERVER"))
	if server == "" {
		return nil, errors.New("SSH_SERVER is not set")
	}

	user, host := parseServer(server)
	if host == "" {
		return nil, errors.New("SSH_SERVER is empty")
	}
	if user == "" {
		user = strings.TrimSpace(os.Getenv("SSH_USER"))
	}
	if user == "" {
		user = strings.TrimSpace(os.Getenv("USER"))
	}
	if user == "" {
		user = strings.TrimSpace(os.Getenv("USERNAME"))
	}
	if user == "" {
		return nil, errors.New("SSH user is not set; provide user@host in SSH_SERVER or set SSH_USER")
	}

	port := uint(22)
	if portStr := strings.TrimSpace(os.Getenv("SSH_PORT")); portStr != "" {
		portVal, err := strconv.Atoi(portStr)
		if err != nil || portVal <= 0 || portVal > 65535 {
			return nil, fmt.Errorf("invalid SSH_PORT: %q", portStr)
		}
		port = uint(portVal)
	}

	auth, err := loadAuth()
	if err != nil {
		return nil, err
	}

	return &sshConfig{User: user, Host: host, Port: port, Auth: auth}, nil
}

func parseServer(server string) (string, string) {
	parts := strings.SplitN(server, "@", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", server
}

func loadAuth() (goph.Auth, error) {
	var auth goph.Auth

	keyPath := strings.TrimSpace(os.Getenv("SSH_KEY"))
	if keyPath != "" {
		passphrase := os.Getenv("SSH_PASSPHRASE")
		if passphrase == "" {
			passphrase = os.Getenv("SSH_KEY_PASSPHRASE")
		}
		keyAuth, err := goph.Key(keyPath, passphrase)
		if err != nil {
			return nil, fmt.Errorf("failed to load SSH_KEY: %w", err)
		}
		auth = append(auth, keyAuth...)
	}

	password := os.Getenv("SSH_PASSWORD")
	if password != "" {
		auth = append(auth, goph.KeyboardInteractive(password)...)
	}

	if len(auth) == 0 {
		return nil, errors.New("no SSH auth configured; set SSH_KEY or SSH_PASSWORD")
	}

	return auth, nil
}

func authFromParams(keyPath, passphrase, password string) (goph.Auth, error) {
	var auth goph.Auth

	keyPath = strings.TrimSpace(keyPath)
	if keyPath != "" {
		keyAuth, err := goph.Key(keyPath, passphrase)
		if err != nil {
			return nil, fmt.Errorf("failed to load key_path: %w", err)
		}
		auth = append(auth, keyAuth...)
	}

	if password != "" {
		auth = append(auth, goph.KeyboardInteractive(password)...)
	}

	if len(auth) == 0 {
		return nil, errors.New("no auth provided; set key_path or password")
	}

	return auth, nil
}

func uploadPath(client *goph.Client, localPath, remotePath string) (transferStats, error) {
	ftp, err := client.NewSftp()
	if err != nil {
		return transferStats{}, fmt.Errorf("sftp init: %w", err)
	}
	defer ftp.Close()

	info, err := os.Stat(localPath)
	if err != nil {
		return transferStats{}, err
	}

	if info.IsDir() {
		return uploadDir(ftp, localPath, remotePath)
	}

	resolvedRemote, err := resolveRemoteFilePath(ftp, localPath, remotePath)
	if err != nil {
		return transferStats{}, err
	}

	var stats transferStats
	n, err := copyLocalToRemote(ftp, localPath, resolvedRemote, info.Mode().Perm())
	if err != nil {
		return transferStats{}, err
	}
	stats.Files = 1
	stats.Bytes = n
	return stats, nil
}

func downloadPath(client *goph.Client, remotePath, localPath string) (transferStats, error) {
	ftp, err := client.NewSftp()
	if err != nil {
		return transferStats{}, fmt.Errorf("sftp init: %w", err)
	}
	defer ftp.Close()

	info, err := ftp.Stat(remotePath)
	if err != nil {
		return transferStats{}, err
	}

	if info.IsDir() {
		return downloadDir(ftp, remotePath, localPath)
	}

	resolvedLocal, err := resolveLocalFilePath(localPath, remotePath)
	if err != nil {
		return transferStats{}, err
	}

	var stats transferStats
	n, err := copyRemoteToLocal(ftp, remotePath, resolvedLocal, info.Mode().Perm())
	if err != nil {
		return transferStats{}, err
	}
	stats.Files = 1
	stats.Bytes = n
	return stats, nil
}

func uploadDir(ftp *sftp.Client, localRoot, remoteRoot string) (transferStats, error) {
	var stats transferStats
	remoteRoot = path.Clean(remoteRoot)

	walkErr := filepath.WalkDir(localRoot, func(localPath string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(localRoot, localPath)
		if err != nil {
			return err
		}

		remotePath := remoteRoot
		if rel != "." {
			remotePath = path.Join(remoteRoot, filepath.ToSlash(rel))
		}

		if entry.IsDir() {
			if err := ftp.MkdirAll(remotePath); err != nil {
				return err
			}
			info, err := entry.Info()
			if err == nil {
				_ = ftp.Chmod(remotePath, info.Mode().Perm())
			}
			stats.Dirs++
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			return err
		}

		n, err := copyLocalToRemote(ftp, localPath, remotePath, info.Mode().Perm())
		if err != nil {
			return err
		}

		stats.Files++
		stats.Bytes += n
		return nil
	})

	if walkErr != nil {
		return transferStats{}, walkErr
	}

	return stats, nil
}

func downloadDir(ftp *sftp.Client, remoteRoot, localRoot string) (transferStats, error) {
	var stats transferStats
	remoteRoot = path.Clean(remoteRoot)

	info, err := ftp.Stat(remoteRoot)
	if err != nil {
		return transferStats{}, err
	}
	if !info.IsDir() {
		return transferStats{}, fmt.Errorf("remote path is not a directory: %s", remoteRoot)
	}

	if err := os.MkdirAll(localRoot, info.Mode().Perm()); err != nil {
		return transferStats{}, err
	}
	stats.Dirs++

	walker := ftp.Walk(remoteRoot)
	for walker.Step() {
		if err := walker.Err(); err != nil {
			return transferStats{}, err
		}

		remotePath := walker.Path()
		rel, err := remoteRel(remoteRoot, remotePath)
		if err != nil {
			return transferStats{}, err
		}
		if rel == "." {
			continue
		}

		info := walker.Stat()
		localPath := filepath.Join(localRoot, filepath.FromSlash(rel))

		if info.IsDir() {
			if err := os.MkdirAll(localPath, info.Mode().Perm()); err != nil {
				return transferStats{}, err
			}
			stats.Dirs++
			continue
		}

		if info.Mode()&os.ModeSymlink != 0 {
			return transferStats{}, fmt.Errorf("symlink not supported: %s", remotePath)
		}

		n, err := copyRemoteToLocal(ftp, remotePath, localPath, info.Mode().Perm())
		if err != nil {
			return transferStats{}, err
		}

		stats.Files++
		stats.Bytes += n
	}

	return stats, nil
}

func resolveRemoteFilePath(ftp *sftp.Client, localPath, remotePath string) (string, error) {
	if strings.HasSuffix(remotePath, "/") {
		return path.Join(remotePath, filepath.Base(localPath)), nil
	}

	info, err := ftp.Stat(remotePath)
	if err == nil {
		if info.IsDir() {
			return path.Join(remotePath, filepath.Base(localPath)), nil
		}
		return remotePath, nil
	}
	if !isNotExist(err) {
		return "", err
	}

	return remotePath, nil
}

func resolveLocalFilePath(localPath, remotePath string) (string, error) {
	if localPath == "" {
		return "", errors.New("local path is empty")
	}

	if strings.HasSuffix(localPath, string(filepath.Separator)) || strings.HasSuffix(localPath, "/") {
		return filepath.Join(localPath, path.Base(remotePath)), nil
	}

	info, err := os.Stat(localPath)
	if err == nil && info.IsDir() {
		return filepath.Join(localPath, path.Base(remotePath)), nil
	}

	if err != nil && !isNotExist(err) {
		return "", err
	}

	return localPath, nil
}

func copyLocalToRemote(ftp *sftp.Client, localPath, remotePath string, perm fs.FileMode) (int64, error) {
	if err := ftp.MkdirAll(path.Dir(remotePath)); err != nil {
		return 0, err
	}

	localFile, err := os.Open(localPath)
	if err != nil {
		return 0, err
	}
	defer localFile.Close()

	remoteFile, err := ftp.Create(remotePath)
	if err != nil {
		return 0, err
	}

	n, err := io.Copy(remoteFile, localFile)
	closeErr := remoteFile.Close()
	if err != nil {
		return n, err
	}
	if closeErr != nil {
		return n, closeErr
	}

	_ = ftp.Chmod(remotePath, perm)
	return n, nil
}

func copyRemoteToLocal(ftp *sftp.Client, remotePath, localPath string, perm fs.FileMode) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(localPath), 0755); err != nil {
		return 0, err
	}

	remoteFile, err := ftp.Open(remotePath)
	if err != nil {
		return 0, err
	}
	defer remoteFile.Close()

	localFile, err := os.OpenFile(localPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return 0, err
	}

	n, err := io.Copy(localFile, remoteFile)
	closeErr := localFile.Close()
	if err != nil {
		return n, err
	}
	if closeErr != nil {
		return n, closeErr
	}

	return n, nil
}

func isNotExist(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, os.ErrNotExist) || os.IsNotExist(err)
}

func remoteRel(root, full string) (string, error) {
	root = path.Clean(root)
	full = path.Clean(full)

	if root == "." {
		return full, nil
	}
	if full == root {
		return ".", nil
	}

	prefix := root + "/"
	if root == "/" {
		prefix = "/"
	}
	if strings.HasPrefix(full, prefix) {
		return strings.TrimPrefix(full, prefix), nil
	}

	return "", fmt.Errorf("path %q is not under %q", full, root)
}
