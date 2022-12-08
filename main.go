package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	mapMutex        *sync.Mutex
	ratelimits      map[string]int
	clientAddresses map[string]*url.URL
)

func getCounter(ip string) int {
	mapMutex.Lock()
	counter, ok := ratelimits[ip]
	mapMutex.Unlock()
	if !ok {
		return 0
	}
	return counter
}

func setCounter(ip string, counter int) {
	mapMutex.Lock()
	ratelimits[ip] = counter
	mapMutex.Unlock()
}

func handleClient(writer http.ResponseWriter, request *http.Request) {
	if request.Method == "GET" {
		fmt.Fprintf(writer, "<!DOCTYPE html><form action=\"/__gopherproxy__\" method=\"POST\"><label for=\"url\">URL </label><input id=\"url\" name=\"url\"></input><input type=\"submit\" value=\"Visit\"></form>")
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

		ip := strings.Split(request.RemoteAddr, ":")[0]
		clientAddresses[ip] = parsedUrl
		fmt.Printf("%v is now assigned to %v\n", ip, parsedUrl)
		fmt.Fprintf(writer, "<!DOCTYPE html><meta http-equiv=\"Refresh\" content=\"0; url='/'\"/>")
	}
}

func proxyRequest(writer http.ResponseWriter, request *http.Request) {
	session := rand.Intn(int(math.Pow(2, 31)))

	ip := strings.Split(request.RemoteAddr, ":")[0]
	for getCounter(ip) >= 25 {
		time.Sleep(1 * time.Second)
	}
	setCounter(ip, getCounter(ip)+1)
	parsedUrl, ok := clientAddresses[ip]
	if !ok {
		fmt.Fprintf(writer, "<!DOCTYPE html><meta http-equiv=\"Refresh\" content=\"0; url='/__gopherproxy__'\"/>")
		return
	}
	url := parsedUrl.String() + request.URL.Path
	if len(url) > 6969 {
		fmt.Fprintf(writer, "Don't try to exploit me!")
		return
	}
	fmt.Printf("[%v] %v is sending a %v request to %v...\n", session, ip, request.Method, url)

	client := http.Client{}
	newRequest, _ := http.NewRequest(request.Method, url, nil)
	newRequest.Header.Add("Handled-By", "GopherProxy")
	for key, value := range request.Header {
		key = strings.ToLower(key)
		if key == "origin" || key == "referer" {
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

			total += read
			fmt.Printf("[%v] Read %v bytes from server (%v total)\n", session, read, total)
			_, err = writer.Write(buffer[:read])
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
	clientAddresses = make(map[string]*url.URL)
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
		time.Sleep(1 * time.Second)
		mapMutex.Lock()
		for ip, ratelimit := range ratelimits {
			if ratelimit == 0 {
				delete(ratelimits, ip)
			} else {
				ratelimits[ip] = ratelimit - 1
			}
		}
		mapMutex.Unlock()
	}
}
