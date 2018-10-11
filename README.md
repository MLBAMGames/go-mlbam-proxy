# mlbam proxy
reverse proxy for any sites, originally made for mlbgames and nhlgames

`mlbamproxy.exe -p 8080 -d example.ddns.net -s google.com,facebook.com,twitter.com`

```
-d string
      Destination domain to forward source domains requests to.
-p int
      Port used by the local proxy (default 17070)
-s string
      Source domains to redirect requests from, separated by commas.
 ```
