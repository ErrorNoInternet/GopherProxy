# GopherProxy
GopherProxy is a proxy written in Go that allows you to enter in any website you want, and make requests using the server GopherProxy is hosted on.

It keeps track of your IP and user agent, and uses that information to identify you. Once you visit the GopherProxy website, it will ask you for the website you want to visit, then it will link your fingerprint (IP + user agent) with the website you entered. GopherProxy will automatically reload the page, identify you, and display the contents of the website you (IP + user agent) requested for.
