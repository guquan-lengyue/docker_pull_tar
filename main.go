package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	url_util "net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
)

const VERSION = "v1.0.0"
const tmpDir = "tmp"

var (
	stopEvent = struct {
		sync.Mutex
		set bool
	}{}
)

type RegistryInfo struct {
	Registry   string
	Repository string
	Image      string
	Tag        string
}

type Manifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	Config        Descriptor        `json:"config"`
	Layers        []Descriptor      `json:"layers"`
	Manifests     []Manifest        `json:"manifests,omitempty"`
	Annotations   map[string]string `json:"annotations,omitempty"`
	Platform      map[string]string `json:"platform,omitempty"`
	Digest        string            `json:"digest,omitempty"`
}

type Descriptor struct {
	MediaType string `json:"mediaType"`
	Size      int64  `json:"size"`
	Digest    string `json:"digest"`
	Platform  *struct {
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
	} `json:"platform,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

func createHTTPClient() *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // 禁用SSL验证
		},
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

func parseImageInput(image string, customRegistry string) (RegistryInfo, error) {
	var info RegistryInfo

	// 检查是否包含私有仓库地址
	if strings.Contains(image, "/") {
		parts := strings.SplitN(image, "/", 2)
		firstPart := parts[0]
		if strings.Contains(firstPart, ".") || strings.Contains(firstPart, ":") {
			// 私有仓库格式
			info.Registry = firstPart
			remainder := parts[1]

			tagParts := strings.Split(remainder, ":")
			repoPart := tagParts[0]
			if len(tagParts) > 1 {
				info.Tag = tagParts[1]
			} else {
				info.Tag = "latest"
			}

			info.Repository = repoPart
			lastSlash := strings.LastIndex(repoPart, "/")
			if lastSlash == -1 {
				info.Image = repoPart
			} else {
				info.Image = repoPart[lastSlash+1:]
			}
			return info, nil
		}
	}

	// 标准Docker Hub格式
	if customRegistry != "" {
		info.Registry = customRegistry
	} else {
		info.Registry = "registry-1.docker.io"
	}

	tagParts := strings.Split(image, ":")
	repoPart := tagParts[0]
	if len(tagParts) > 1 {
		info.Tag = tagParts[1]
	} else {
		info.Tag = "latest"
	}

	if !strings.Contains(repoPart, "/") {
		info.Repository = "library/" + repoPart
		info.Image = repoPart
	} else {
		info.Repository = repoPart
		lastSlash := strings.LastIndex(repoPart, "/")
		info.Image = repoPart[lastSlash+1:]
	}

	return info, nil
}

func getAuthHeader(client *http.Client, registry, repository, username, password string) (map[string]string, error) {
	url := fmt.Sprintf("https://%s/v2/", registry)
	resp, err := client.Head(url)
	if err != nil {
		return nil, fmt.Errorf("请求仓库失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return map[string]string{"Accept": "application/vnd.docker.distribution.manifest.v2+json"}, nil
	}

	if resp.StatusCode != http.StatusUnauthorized {
		return nil, fmt.Errorf("获取认证信息失败，状态码: %d", resp.StatusCode)
	}

	authHeader := resp.Header.Get("WWW-Authenticate")
	if authHeader == "" {
		return nil, errors.New("未找到认证信息")
	}

	// 解析认证信息
	parts := strings.Split(authHeader, " ")
	if len(parts) < 2 || parts[0] != "Bearer" {
		return nil, errors.New("不支持的认证方式")
	}

	params := parseAuthParams(parts[1])
	realm, ok1 := params["realm"]
	service, ok2 := params["service"]
	if !ok1 || !ok2 {
		return nil, errors.New("认证参数不完整")
	}

	// 构建认证请求URL
	authURL := fmt.Sprintf("%s?service=%s&scope=repository:%s:pull",
		realm, url_util.QueryEscape(service), url_util.QueryEscape(repository))

	// 创建请求
	req, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		return nil, err
	}

	// 添加基础认证
	if username != "" && password != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, password)))
		req.Header.Add("Authorization", fmt.Sprintf("Basic %s", auth))
	}

	resp, err = client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("认证请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("认证失败，状态码: %d", resp.StatusCode)
	}

	// 解析token
	var tokenResp struct {
		Token string `json:"token"`
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("解析token失败: %v", err)
	}

	return map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", tokenResp.Token),
		"Accept":        "application/vnd.docker.distribution.manifest.v2+json",
	}, nil
}

func parseAuthParams(s string) map[string]string {
	params := make(map[string]string)
	parts := strings.Split(s, ",")
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			key := strings.TrimSpace(kv[0])
			value := strings.Trim(kv[1], "\" ")
			params[key] = value
		}
	}
	return params
}

func fetchManifest(client *http.Client, registry, repository, tag string, headers map[string]string) (*Manifest, error) {
	url := fmt.Sprintf("https://%s/v2/%s/manifests/%s", registry, repository, tag)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("获取清单失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取清单失败，状态码: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var manifest Manifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return nil, fmt.Errorf("解析清单失败: %v", err)
	}

	return &manifest, nil
}

func selectManifest(manifests []Manifest, arch string) *Manifest {
	for _, m := range manifests {
		if m.Platform == nil {
			continue
		}
		if m.Platform["os"] == "linux" && m.Platform["architecture"] == arch {
			return &m
		}
		if m.Annotations != nil && m.Annotations["com.docker.official-images.bashbrew.arch"] == arch {
			return &m
		}
	}
	return nil
}

func downloadFile(client *http.Client, url string, headers map[string]string, savePath string, desc string) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("下载请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败，状态码: %d", resp.StatusCode)
	}

	// 创建目录
	if err := os.MkdirAll(filepath.Dir(savePath), 0755); err != nil {
		return err
	}

	file, err := os.Create(savePath)
	if err != nil {
		return err
	}
	defer file.Close()

	var bar *progressbar.ProgressBar
	if resp.ContentLength > 0 {
		bar = progressbar.NewOptions64(resp.ContentLength,
			progressbar.OptionSetDescription(desc),
			progressbar.OptionShowBytes(true),
			progressbar.OptionSetWidth(10),
			progressbar.OptionThrottle(65*time.Millisecond),
			progressbar.OptionShowCount(),
			progressbar.OptionClearOnFinish(),
		)
	}

	buf := make([]byte, 1024*1024)
	for {
		// 检查是否需要停止
		stopEvent.Lock()
		if stopEvent.set {
			stopEvent.Unlock()
			return errors.New("下载被取消")
		}
		stopEvent.Unlock()

		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, err := file.Write(buf[:n]); err != nil {
				return err
			}
			if bar != nil {
				bar.Add(n)
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
	}

	return nil
}

func downloadLayers(client *http.Client, registry, repository string, layers []Descriptor,
	authHeaders map[string]string, imgdir string, imgparts []string, img, tag string) error {

	// 下载配置文件
	configURL := fmt.Sprintf("https://%s/v2/%s/blobs/%s", registry, repository, layers[0].Digest)
	configFilename := strings.TrimPrefix(layers[0].Digest, "sha256:") + ".json"
	configPath := filepath.Join(imgdir, configFilename)

	log.Printf("下载配置文件: %s", configFilename)
	if err := downloadFile(client, configURL, authHeaders, configPath, "Config"); err != nil {
		return fmt.Errorf("配置文件下载失败: %v", err)
	}

	// 准备repo标签
	var repoTag string
	if len(imgparts) > 0 {
		repoTag = fmt.Sprintf("%s/%s:%s", strings.Join(imgparts, "/"), img, tag)
	} else {
		repoTag = fmt.Sprintf("%s:%s", img, tag)
	}

	// 准备层信息
	content := map[string]any{
		"Config":   configFilename,
		"RepoTags": []string{repoTag},
		"Layers":   []string{},
	}

	var parentID string
	layerJSONMap := make(map[string]map[string]any)

	// 下载层文件
	var wg sync.WaitGroup
	errChan := make(chan error, len(layers)-1) // 第一个是配置文件，不算层
	sem := make(chan struct{}, 4)              // 限制并发数

	for i, layer := range layers[1:] { // 跳过配置文件
		sem <- struct{}{}
		wg.Add(1)
		go func(layer Descriptor, index int) {
			defer wg.Done()
			defer func() { <-sem }()

			// 检查是否需要停止
			stopEvent.Lock()
			if stopEvent.set {
				stopEvent.Unlock()
				errChan <- errors.New("下载被取消")
				return
			}
			stopEvent.Unlock()

			// 生成伪层ID
			h := sha256.New()
			h.Write([]byte(parentID + "\n" + layer.Digest + "\n"))
			fakeLayerID := fmt.Sprintf("%x", h.Sum(nil))

			layerDir := filepath.Join(imgdir, fakeLayerID)
			if err := os.MkdirAll(layerDir, 0755); err != nil {
				errChan <- fmt.Errorf("创建层目录失败: %v", err)
				return
			}

			// 保存层信息
			layerJSONMap[fakeLayerID] = map[string]any{
				"id":     fakeLayerID,
				"parent": parentID,
			}

			// 下载层文件
			url := fmt.Sprintf("https://%s/v2/%s/blobs/%s", registry, repository, layer.Digest)
			savePath := filepath.Join(layerDir, "layer_gzip.tar")

			desc := fmt.Sprintf("Layer %d/%d", index+1, len(layers)-1)
			if err := downloadFile(client, url, authHeaders, savePath, desc); err != nil {
				errChan <- fmt.Errorf("层文件下载失败: %v", err)
				return
			}
		}(layer, i)
	}

	// 等待所有下载完成
	go func() {
		wg.Wait()
		close(errChan)
	}()

	// 检查错误
	for err := range errChan {
		if err != nil {
			return err
		}
	}

	// 处理层文件
	layersList := make([]string, 0, len(layerJSONMap))
	for fakeLayerID := range layerJSONMap {
		layerDir := filepath.Join(imgdir, fakeLayerID)
		gzPath := filepath.Join(layerDir, "layer_gzip.tar")
		tarPath := filepath.Join(layerDir, "layer.tar")

		// 解压gzip
		gzFile, err := os.Open(gzPath)
		if err != nil {
			return fmt.Errorf("打开压缩文件失败: %v", err)
		}

		gzReader, err := gzip.NewReader(gzFile)
		if err != nil {
			gzFile.Close()
			return fmt.Errorf("创建gzip读取器失败: %v", err)
		}

		tarFile, err := os.Create(tarPath)
		if err != nil {
			gzReader.Close()
			gzFile.Close()
			return fmt.Errorf("创建tar文件失败: %v", err)
		}

		if _, err := io.Copy(tarFile, gzReader); err != nil {
			tarFile.Close()
			gzReader.Close()
			gzFile.Close()
			return fmt.Errorf("解压文件失败: %v", err)
		}

		tarFile.Close()
		gzReader.Close()
		gzFile.Close()
		os.Remove(gzPath)

		// 保存层JSON
		jsonPath := filepath.Join(layerDir, "json")
		jsonData, err := json.Marshal(layerJSONMap[fakeLayerID])
		if err != nil {
			return fmt.Errorf("序列化层信息失败: %v", err)
		}
		if err := os.WriteFile(jsonPath, jsonData, 0644); err != nil {
			return fmt.Errorf("写入层信息失败: %v", err)
		}

		layersList = append(layersList, fmt.Sprintf("%s/layer.tar", fakeLayerID))
		parentID = fakeLayerID
	}

	content["Layers"] = layersList

	// 写入manifest.json
	manifestPath := filepath.Join(imgdir, "manifest.json")
	manifestData, err := json.Marshal([]any{content})
	if err != nil {
		return fmt.Errorf("序列化manifest失败: %v", err)
	}
	if err := os.WriteFile(manifestPath, manifestData, 0644); err != nil {
		return fmt.Errorf("写入manifest失败: %v", err)
	}

	// 写入repositories
	reposPath := filepath.Join(imgdir, "repositories")
	reposData := map[string]map[string]string{
		repository: {tag: parentID},
	}
	if !strings.Contains(repository, "/") {
		reposData[img] = reposData[repository]
		delete(reposData, repository)
	}

	reposJSON, err := json.Marshal(reposData)
	if err != nil {
		return fmt.Errorf("序列化仓库信息失败: %v", err)
	}
	if err := os.WriteFile(reposPath, reposJSON, 0644); err != nil {
		return fmt.Errorf("写入仓库信息失败: %v", err)
	}

	return nil
}

func createImageTar(imgdir, repository, tag, arch string) (string, error) {
	safeRepo := strings.ReplaceAll(repository, "/", "_")
	tarName := fmt.Sprintf("%s_%s_%s.tar", safeRepo, tag, arch)

	file, err := os.Create(tarName)
	if err != nil {
		return "", err
	}
	defer file.Close()

	tw := tar.NewWriter(file)
	defer tw.Close()

	// 递归添加目录内容
	return tarName, filepath.Walk(imgdir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 跳过目录本身
		if path == imgdir {
			return nil
		}

		header, err := tar.FileInfoHeader(info, info.Name())
		if err != nil {
			return err
		}

		// 调整名称，去掉tmp前缀
		relPath, err := filepath.Rel(imgdir, path)
		if err != nil {
			return err
		}
		header.Name = relPath

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if !info.Mode().IsRegular() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		_, err = io.Copy(tw, file)
		return err
	})
}

func cleanupTmpDir() {
	if err := os.RemoveAll(tmpDir); err != nil {
		log.Printf("清理临时目录失败: %v", err)
	} else {
		log.Println("临时目录已清理")
	}
}

func main() {
	// 命令行参数
	var (
		image       string
		quiet       bool
		customReg   string
		arch        string
		username    string
		password    string
		showVersion bool
		debug       bool
	)
	flag.StringVar(&image, "i", "", "Docker 镜像名称（例如：nginx:latest 或 harbor.abc.com/abc/nginx:1.26.0）")
	flag.BoolVar(&quiet, "q", false, "静默模式，减少交互")
	flag.StringVar(&customReg, "r", "", "自定义仓库地址（例如：harbor.abc.com）")
	flag.StringVar(&arch, "a", "", "架构,默认：amd64,常见：amd64, arm64v8等")
	flag.StringVar(&username, "u", "", "Docker 仓库用户名")
	flag.StringVar(&password, "p", "", "Docker 仓库密码")
	flag.BoolVar(&showVersion, "v", false, "显示版本信息")
	flag.BoolVar(&debug, "debug", false, "启用调试模式")
	flag.Parse()

	// 显示版本
	if showVersion {
		fmt.Printf("docker-image-puller %s\n", VERSION)
		return
	}

	log.Printf("欢迎使用 Docker 镜像拉取工具 %s", VERSION)

	// 获取镜像名称
	if image == "" {
		fmt.Print("请输入 Docker 镜像名称（例如：nginx:latest 或 harbor.abc.com/abc/nginx:1.26.0）：")
		fmt.Scanln(&image)
		if image == "" {
			log.Fatal("错误：镜像名称是必填项。")
		}
	}

	// 获取自定义仓库地址
	if customReg == "" && !quiet {
		fmt.Print("请输入自定义仓库地址: （默认 dockerhub）")
		fmt.Scanln(&customReg)
	}

	// 解析镜像信息
	regInfo, err := parseImageInput(image, customReg)
	if err != nil {
		log.Fatalf("解析镜像信息失败: %v", err)
	}

	// 获取认证信息
	if username == "" && !quiet {
		fmt.Printf("请输入 %s 仓库的用户名: ", regInfo.Registry)
		fmt.Scanln(&username)
	}
	if password == "" && !quiet {
		fmt.Printf("请输入 %s 仓库的密码: ", regInfo.Registry)
		fmt.Scanln(&password)
	}

	// 创建HTTP客户端
	client := createHTTPClient()

	// 获取认证头
	authHeaders, err := getAuthHeader(client, regInfo.Registry, regInfo.Repository, username, password)
	if err != nil {
		log.Fatalf("获取认证信息失败: %v", err)
	}

	// 获取清单
	manifest, err := fetchManifest(client, regInfo.Registry, regInfo.Repository, regInfo.Tag, authHeaders)
	if err != nil {
		log.Fatalf("获取镜像清单失败: %v", err)
	}

	// 处理多架构镜像
	var targetManifest *Manifest
	if len(manifest.Manifests) > 0 {
		// 收集可用架构
		var archs []string
		for _, m := range manifest.Manifests {
			if m.Platform != nil && m.Platform["os"] == "linux" {
				archs = append(archs, m.Platform["architecture"])
			}
		}

		if len(archs) > 0 {
			log.Printf("可用架构: %s", strings.Join(archs, ", "))
		}

		// 选择架构
		if arch == "" {
			if len(archs) == 1 {
				arch = archs[0]
				log.Printf("自动选择唯一架构: %s", arch)
			} else {
				fmt.Printf("请输入架构（可选: %s，默认: amd64）：", strings.Join(archs, ", "))
				fmt.Scanln(&arch)
				if arch == "" {
					arch = "amd64"
				}
			}
		}

		// 获取对应架构的清单
		selected := selectManifest(manifest.Manifests, arch)
		if selected == nil {
			log.Fatalf("找不到架构 %s 的镜像", arch)
		}

		targetManifest, err = fetchManifest(client, regInfo.Registry, regInfo.Repository, selected.Digest, authHeaders)
		if err != nil {
			log.Fatalf("获取架构清单失败: %v", err)
		}
	} else {
		targetManifest = manifest
		if arch == "" {
			arch = "amd64" // 默认架构
		}
	}

	if len(targetManifest.Layers) == 0 {
		log.Fatal("清单中没有找到镜像层")
	}

	// 显示信息
	log.Printf("仓库地址：%s", regInfo.Registry)
	log.Printf("镜像：%s", regInfo.Repository)
	log.Printf("标签：%s", regInfo.Tag)
	log.Printf("架构：%s", arch)

	// 准备下载目录
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		log.Fatalf("创建临时目录失败: %v", err)
	}

	// 准备imgparts
	var imgparts []string
	if regInfo.Registry == "registry-1.docker.io" && strings.HasPrefix(regInfo.Repository, "library/") {
		imgparts = []string{}
	} else {
		parts := strings.Split(regInfo.Repository, "/")
		if len(parts) > 1 {
			imgparts = parts[:len(parts)-1]
		} else {
			imgparts = []string{}
		}
	}

	// 下载镜像层
	log.Println("开始下载镜像层...")
	if err := downloadLayers(client, regInfo.Registry, regInfo.Repository,
		targetManifest.Layers, authHeaders, tmpDir, imgparts, regInfo.Image, regInfo.Tag); err != nil {
		log.Fatalf("下载镜像层失败: %v", err)
	}

	// 打包镜像
	outputFile, err := createImageTar(tmpDir, regInfo.Repository, regInfo.Tag, arch)
	if err != nil {
		log.Fatalf("打包镜像失败: %v", err)
	}

	log.Printf("镜像已保存为: %s", outputFile)
	log.Printf("可使用以下命令导入镜像: docker load -i %s", outputFile)

	if regInfo.Registry != "registry-1.docker.io" && regInfo.Registry != "docker.io" {
		log.Printf("您可能需要: docker tag %s:%s %s/%s:%s",
			regInfo.Repository, regInfo.Tag,
			regInfo.Registry, regInfo.Repository, regInfo.Tag)
	}

	// 清理临时文件
	cleanupTmpDir()

	fmt.Println("按任意键退出程序...")
	fmt.Scanln()
}
