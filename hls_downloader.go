package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

// 全局常量和变量
const (
	MaxConcurrentDownloads = 8               // 最大并发数
	DownloadInterval       = 5 * time.Second // 重试时间 sec
)

var downloadedSegments = make(map[string]bool) // 去重
var downloadedMutex sync.Mutex                 // 互斥锁

// 下载主函数
func loopDownloadHLS(m3u8URL, tempDir string) error {
	fmt.Printf("开始循环下载 HLS 流: %s\n", m3u8URL)
	fmt.Printf("媒体片段将保存到目录: %s\n", tempDir)

	// 创建临时目录
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return fmt.Errorf("创建保存目录失败: %w", err)
	}

	// 主循环：持续处理 M3U8 文件
	for {
		err := processM3U8(m3u8URL, tempDir)
		if err != nil {
			fmt.Printf("处理 M3U8 文件时发生错误: %v。将在 %v 后重试。\n", err, DownloadInterval)
		}

		time.Sleep(DownloadInterval)
	}
}

// 处理 M3U8 的单次迭代
func processM3U8(m3u8URL, tempDir string) error {
	// 1. 下载主 M3U8 文件
	resp, err := http.Get(m3u8URL)
	if err != nil {
		return fmt.Errorf("下载 M3U8 文件失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("M3U8 下载返回非 200 状态码: %d", resp.StatusCode)
	}

	// 2. 解析 M3U8 文件，获取 URL 列表
	urls, isMasterPlaylist, err := parseM3U8(resp.Body, m3u8URL)
	if err != nil {
		return fmt.Errorf("解析 M3U8 失败: %w", err)
	}
	if len(urls) == 0 {
		return fmt.Errorf("M3U8 中未找到任何链接")
	}

	// 处理主播放列表
	if isMasterPlaylist {
		// 选择主播放列表中的第一个文件进行设置
		selectedMediaURL := urls[0]
		fmt.Printf("[%s] 发现主播放列表，切换到媒体列表: %s\n", time.Now().Format("15:04:05"), selectedMediaURL)

		// 递归查询
		return processM3U8(selectedMediaURL, tempDir)
	}

	// 3. 筛选出新的、未下载过的 TS 文件
	newTSURLs := filterNewSegments(urls) // 此时 urls 已经保证是 tsURLs

	if len(newTSURLs) == 0 {
		fmt.Printf("[%s] 未发现新片段，等待下次检查...\n", time.Now().Format("15:04:05"))
		return nil
	}

	fmt.Printf("[%s] 发现 %d 个新片段，开始下载...\n", time.Now().Format("15:04:05"), len(newTSURLs))

	// 4. 并发下载所有新 TS 文件
	err = concurrentDownloadNew(newTSURLs, tempDir)
	if err != nil {
		return fmt.Errorf("并发下载新 TS 文件失败: %w", err)
	}

	return nil
}

// 解析m3u8文件，返回URL列表和是否为主播放列表的标志。
// 如果是主列表，返回子 M3U8 链接列表；如果是媒体列表，返回媒体片段链接列表。
func parseM3U8(body io.Reader, baseURL string) ([]string, bool, error) {
	// 1. 读取整个 M3U8 内容到内存，以便进行标签搜索（类型识别）
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return nil, false, fmt.Errorf("读取 M3U8 内容失败: %w", err)
	}
	content := string(bodyBytes)

	// 2. 通过 HLS 标签识别列表类型
	isMasterPlaylist := strings.Contains(content, "#EXT-X-STREAM-INF") // 主列表标志
	isMediaPlaylist := strings.Contains(content, "#EXTINF")            // 媒体列表标志

	// 3. 健壮性检查：HLS 规范不允许混用 Master 和 Media 标签
	if isMasterPlaylist && isMediaPlaylist {
		// 遇到混合列表，通常倾向于按媒体列表处理，并忽略 Master 标签
		fmt.Printf("警告: M3U8 文件同时包含 Master/Media 标签，按 Media 列表处理。\n")
		isMasterPlaylist = false
	} else if !isMasterPlaylist && !isMediaPlaylist {
		return nil, false, fmt.Errorf("M3U8 文件缺少 EXT-X-STREAM-INF 或 EXTINF 标签，无法识别列表类型")
	}

	// 4. 初始化 URL 解析器
	var urls []string
	scanner := bufio.NewScanner(strings.NewReader(content))
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, false, fmt.Errorf("解析基础 URL 失败: %w", err)
	}

	// 5. 逐行扫描，提取所有非标签/非注释的 URL
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// 跳过注释行、标签行和空行
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		// 解析相对路径并合并到完整 URL
		u, err := base.Parse(line)
		if err != nil {
			fmt.Printf("警告: 无法解析 URL '%s': %v\n", line, err)
			continue
		}

		// 此时，非注释非标签的行，一定是 M3U8 链接或媒体片段链接
		urls = append(urls, u.String())
	}

	if err := scanner.Err(); err != nil {
		return nil, false, err
	}

	if len(urls) == 0 {
		return nil, false, fmt.Errorf("M3U8 文件中未找到任何有效链接")
	}

	// 6. 返回结果：urls 包含所有提取的链接，isMasterPlaylist 标志列表类型
	return urls, isMasterPlaylist, nil
}

// 筛选出尚未下载的片段 URL
func filterNewSegments(tsURLs []string) []string {
	downloadedMutex.Lock()
	defer downloadedMutex.Unlock()

	var newURLs []string
	for _, u := range tsURLs {
		if !downloadedSegments[u] {
			newURLs = append(newURLs, u)
			// 立即标记为已发现（即使还未下载），避免下次检查时重复添加
			downloadedSegments[u] = true
		}
	}
	return newURLs
}

// 并发下载新的 TS 文件
func concurrentDownloadNew(tsURLs []string, tempDir string) error {
	var wg sync.WaitGroup
	tsCount := len(tsURLs)
	sem := make(chan struct{}, MaxConcurrentDownloads) // 信号量限制并发数
	errChan := make(chan error, tsCount)               // 用于接收错误

	for i, tsURL := range tsURLs {
		wg.Add(1)
		sem <- struct{}{} // 占用一个信号量

		go func(index int, currentURL string) {
			defer wg.Done()
			defer func() { <-sem }() // 释放信号量

			// 解析 currentURL
			parsedURL, _ := url.Parse(currentURL)

			baseFilename := path.Base(parsedURL.Path)
			if !strings.HasSuffix(baseFilename, ".ts") {
				baseFilename += ".ts" // 确保后缀是 .ts
			}

			// 确保文件名唯一性，使用时间戳 + 序号作为前缀
			uniqueFilename := fmt.Sprintf("%s_%05d_%s", time.Now().Format("20060102_150405"), index, baseFilename)
			filename := path.Join(tempDir, uniqueFilename)

			err := downloadFile(currentURL, filename)
			if err != nil {
				// 将下载失败的片段从 '已下载' 列表中移除，以便下次重试
				downloadedMutex.Lock()
				delete(downloadedSegments, currentURL)
				downloadedMutex.Unlock()

				errChan <- fmt.Errorf("下载片段 %d (%s) 失败: %w", index, currentURL, err)
				return
			}

			// 打印进度
			fmt.Printf("  下载完成: %s\n", uniqueFilename)
		}(i, tsURL)
	}

	// 等待所有协程完成
	wg.Wait()
	close(errChan)

	// 检查是否有错误发生
	select {
	case err := <-errChan:
		return err // 只要有一个错误就返回
	default:
		return nil
	}
}

// 下载单个文件（与前一个示例相同，包含简单重试）
func downloadFile(fileURL string, filepath string) error {
	const maxRetries = 3
	for i := 0; i < maxRetries; i++ {
		resp, err := http.Get(fileURL) // 修正了这里的参数名，使用 fileURL
		if err != nil {
			time.Sleep(time.Second * time.Duration(i+1))
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			if i < maxRetries-1 {
				time.Sleep(time.Second * time.Duration(i+1))
				continue
			}
			return fmt.Errorf("HTTP 状态码错误: %d", resp.StatusCode)
		}

		// 如果文件已存在，则跳过下载，因为我们希望只下载一次
		if _, err := os.Stat(filepath); err == nil {
			return nil // 文件已存在，跳过下载
		}

		out, err := os.Create(filepath)
		if err != nil {
			return err
		}
		defer out.Close()

		_, err = io.Copy(out, resp.Body)
		return err
	}
	return fmt.Errorf("达到最大重试次数，下载失败: %s", fileURL)
}

// 打印帮助文件
func printHelp() {
	appName := path.Base(os.Args[0]) // 获取程序本身的名称

	fmt.Printf("HLS 直播流下载器\n\n")
	fmt.Printf("使用方法:\n")
	fmt.Printf("  %s <M3U8_URL>\n\n", appName)
	fmt.Printf("参数:\n")
	fmt.Printf("  <M3U8_URL>  要下载的 HLS 播放列表 (M3U8) 的完整 URL。\n\n")
	fmt.Printf("示例:\n")
	fmt.Printf("  %s https://example.com/live/stream/playlist.m3u8\n", appName)
}

func deriveOutputDir(hlsURL string) (string, error) {
	// 1. 解析 hlsURL
	parsedURL, err := url.Parse(hlsURL)
	if err != nil {
		return "", fmt.Errorf("解析 URL 失败: %w", err)
	}

	// 2. 获取路径中的文件名 (例如: xxxx.m3u8)
	filename := path.Base(parsedURL.Path)

	if filename == "" || filename == "." || filename == "/" {
		// 如果 URL 路径为空，或者只有斜杠，使用域名作为基础
		baseName := parsedURL.Host
		if baseName == "" {
			return "default_hls_segments", nil
		}

		// 移除可能的端口号
		if colonIndex := strings.LastIndex(baseName, ":"); colonIndex != -1 {
			baseName = baseName[:colonIndex]
		}
		// 替换域名中的点号为下划线
		baseName = strings.ReplaceAll(baseName, ".", "_")

		return fmt.Sprintf("%s_hls_segments", baseName), nil
	}

	// 3. 移除 .m3u8 或 .M3u8 后缀
	baseName := filename
	if strings.HasSuffix(baseName, ".m3u8") || strings.HasSuffix(baseName, ".M3u8") {
		// 移除最后 5 个字符 (.m3u8)
		baseName = baseName[:len(baseName)-5]
	}

	// 4. 清理文件名，确保目录名合法和安全
	// 将非字母数字、非下划线、非破折号的字符替换为下划线
	sanitizedBaseName := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, baseName)

	// 5. 构建最终的 outputDir 名称
	outputDir := fmt.Sprintf("%s_hls_segments", sanitizedBaseName)
	return outputDir, nil
}

func main() {
	var hlsURL string

	// 判断参数长度
	if len(os.Args) > 1 {
		hlsURL = os.Args[1]
	} else {
		printHelp()
		os.Exit(1)
	}

	// 创建输出目录
	outputDir, err := deriveOutputDir(hlsURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: 无法确定下载目录: %v\n", err)
		os.Exit(1)
	}

	// 启动循环下载
	if err := loopDownloadHLS(hlsURL, outputDir); err != nil {
		fmt.Fprintf(os.Stderr, "下载器意外退出: %v\n", err)
		os.Exit(1)
	}
}
