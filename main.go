package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zeebo/xxh3"
)

var (
	mapMutex           *sync.Mutex
	ratelimits         map[string]int
	clientFingerprints map[string]*url.URL
)

func getFingerprint(request *http.Request) string {
	fingerprint := request.RemoteAddr
	if strings.HasPrefix(fingerprint, "172.31") {
		fingerprint = request.Header.Get("X-Forwarded-For")
		if fingerprint == "" {
			fingerprint = request.RemoteAddr
		}
	}
	if strings.Contains(fingerprint, ":") {
		fingerprint = strings.Split(fingerprint, ":")[0]
	}
	fingerprint += request.Header.Get("User-Agent")
	fingerprint = strconv.FormatUint(xxh3.HashString(fingerprint), 10)
	return fingerprint
}

func getCounter(fingerprint string) int {
	mapMutex.Lock()
	counter, ok := ratelimits[fingerprint]
	mapMutex.Unlock()
	if !ok {
		return 0
	}
	return counter
}

func setCounter(fingerprint string, counter int) {
	mapMutex.Lock()
	ratelimits[fingerprint] = counter
	mapMutex.Unlock()
}

func handleClient(writer http.ResponseWriter, request *http.Request) {
	if request.Method == "GET" {
		fmt.Fprintf(writer, "<!DOCTYPE html><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><form action=\"/__gopherproxy__\" method=\"POST\"><label for=\"url\">URL </label><input id=\"url\" name=\"url\"></input><input type=\"submit\" value=\"Visit\"></form>")
	} else if request.Method == "POST" {
		rawUrl, err := ioutil.ReadAll(request.Body)
		if err != nil {
			fmt.Fprintf(writer, err.Error())
			return
		}
		decodedUrl, err := url.QueryUnescape(strings.TrimPrefix(string(rawUrl), "url="))
		if err != nil {
			fmt.Fprintf(writer, err.Error())
			return
		}
		parsedUrl, err := url.Parse(strings.TrimSuffix(decodedUrl, "/"))
		if err != nil {
			fmt.Fprintf(writer, err.Error())
			return
		}

		fingerprint := strings.Split(getFingerprint(request), ":")[0]
		clientFingerprints[fingerprint] = parsedUrl
		fmt.Printf("%v is now assigned to %v\n", fingerprint, parsedUrl)
		fmt.Fprintf(writer, "<!DOCTYPE html><meta http-equiv=\"Refresh\" content=\"0; url='/'\"/>")
	}
}

func proxyRequest(writer http.ResponseWriter, request *http.Request) {
	session := rand.Intn(int(math.Pow(2, 31)))

	fingerprint := strings.Split(getFingerprint(request), ":")[0]
	for getCounter(fingerprint) >= 60 {
		time.Sleep(1 * time.Second)
	}
	setCounter(fingerprint, getCounter(fingerprint)+1)
	parsedUrl, ok := clientFingerprints[fingerprint]
	if !ok {
		fmt.Fprintf(writer, "<!DOCTYPE html><meta http-equiv=\"Refresh\" content=\"0; url='/__gopherproxy__'\"/>")
		return
	}
	url := parsedUrl.Scheme + "://" + parsedUrl.Host + request.URL.Path
	if request.URL.RawQuery != "" {
		url += "?" + request.URL.RawQuery
	}
	if len(url) > 6969 {
		fmt.Fprintf(writer, "Don't try to exploit me!")
		return
	}
	fmt.Printf("[%v] %v is sending a %v request to %v...\n", session, fingerprint, request.Method, url)

	client := http.Client{}
	newRequest, _ := http.NewRequest(request.Method, url, request.Body)
	for key, value := range request.Header {
		key = strings.ToLower(key)
		if key == "accept-encoding" || key == "content-length" || key == "origin" || key == "referer" || key == "cookie" {
			continue
		}
		if key == "host" {
			newRequest.Header.Add(key, parsedUrl.Host)
		} else {
			newRequest.Header.Add(key, value[0])
		}
	}
	response, err := client.Do(newRequest)
	if err != nil {
		fmt.Fprintf(writer, err.Error())
		return
	}

	writer.Header().Add("Handled-By", "GopherProxy")
	for key, value := range response.Header {
		key = strings.ToLower(key)
		if key == "handled-by" && value[0] == "GopherProxy" {
			fmt.Fprintf(writer, "Don't try to exploit me!")
			return
		}
		if key == "content-length" || key == "set-cookie" {
			continue
		}
		writer.Header().Add(key, value[0])
	}
	writer.WriteHeader(response.StatusCode)
	if request.Method == "HEAD" {
		return
	} else {
		reader := bufio.NewReader(response.Body)
		buffer := make([]byte, 1024*1024)
		total := 0
		for {
			read, readErr := reader.Read(buffer)
			modifiedBuffer := bytes.ReplaceAll(buffer[:read], []byte(parsedUrl.Host), []byte(os.Getenv("URL")))

			total += read
			fmt.Printf("[%v] Forwarding %v bytes from server (%v total)\n", session, read, total)
			_, err = writer.Write(modifiedBuffer)
			if err != nil {
				fmt.Printf("[%v] Disconnecting from client: %v\n", session, err)
				break
			}
			writer.(http.Flusher).Flush()

			if readErr != nil {
				break
			}
		}
		fmt.Printf("[%v] Successfully sent %v bytes to client\n", session, total)
	}
}

func main() {
	rand.Seed(time.Now().UnixNano())
	mapMutex = &sync.Mutex{}
	ratelimits = make(map[string]int)
	clientFingerprints = make(map[string]*url.URL)
	go cleanup()

	http.HandleFunc("/__gopherproxy__", handleClient)
	http.HandleFunc("/", proxyRequest)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Printf("Starting server on port %v...\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Printf("Unable to bind address: %v\n", err)
	}
}

func cleanup() {
	for {
		time.Sleep(500 * time.Millisecond)
		mapMutex.Lock()
		for fingerprint, ratelimit := range ratelimits {
			if ratelimit == 0 {
				delete(ratelimits, fingerprint)
			} else {
				ratelimits[fingerprint] = ratelimit - 1
			}
		}
		mapMutex.Unlock()
	}
}
