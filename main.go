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
	"time"
)

var (
	clientAddresses map[string]string
)

func handleClient(writer http.ResponseWriter, request *http.Request) {
	if request.Method == "GET" {
		fmt.Fprintf(writer, "<!DOCTYPE html><form action=\"/__gopherproxy__\" method=\"POST\"><label for=\"url\">URL </label><input id=\"url\" name=\"url\"></input><input type=\"submit\" value=\"Visit\"></form>")
	} else if request.Method == "POST" {
		rawUrl, err := ioutil.ReadAll(request.Body)
		if err != nil {
			fmt.Fprintf(writer, err.Error())
			return
		}
		ip := strings.Split(request.RemoteAddr, ":")[0]
		parsedUrl, err := url.QueryUnescape(strings.TrimPrefix(string(rawUrl), "url="))
		if err != nil {
			fmt.Fprintf(writer, err.Error())
			return
		}
		url := strings.TrimSuffix(parsedUrl, "/")
		clientAddresses[ip] = url
		fmt.Printf("%v is now assigned to %v\n", ip, url)
		fmt.Fprintf(writer, "<!DOCTYPE html><meta http-equiv=\"Refresh\" content=\"0; url='/'\"/>")
	}
}

func proxyRequest(writer http.ResponseWriter, request *http.Request) {
	session := rand.Intn(int(math.Pow(2, 31)))

	ip := strings.Split(request.RemoteAddr, ":")[0]
	url, ok := clientAddresses[ip]
	if !ok {
		fmt.Fprintf(writer, "<!DOCTYPE html><meta http-equiv=\"Refresh\" content=\"0; url='/__gopherproxy__'\"/>")
		return
	}
	url = url + request.URL.Path
	fmt.Printf("[%v] %v is sending a %v request to %v...\n", session, ip, request.Method, url)

	client := http.Client{}
	newRequest, _ := http.NewRequest(request.Method, url, nil)
	for key, value := range request.Header {
		newRequest.Header.Add(key, value[0])
	}
	response, err := client.Do(newRequest)
	if err != nil {
		fmt.Fprintf(writer, err.Error())
		return
	}

	for key, value := range response.Header {
		key = strings.ToLower(key)
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
	clientAddresses = make(map[string]string)

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
