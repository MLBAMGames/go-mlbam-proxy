# mlbam proxy
it's like using the windows hosts file but without the tears. if you are familiar with mitm proxy and its mitmdump command line, it pretty much does the same work but so much faster and without being flagged as a malware. kind of cool for a tool that light. built in golang.

`mlbamproxy -p 17070 -d example.ddns.net -s google.com,facebook.com,twitter.com`

```
-d string
      Destination domain to forward source domains requests to.
-p int
      Port used by the local proxy (default 17070)
-s string
      Source domains to redirect requests from, separated by commas.
 ```

### projects using mlbam proxy
- [NHLGames](https://github.com/NHLGames/NHLGames) windows front end for watching nhl games

> if you are using mlbam proxy in a project please send a pull request to add it to the list.

#### [latest release](https://github.com/jwallet/mlbamproxy/releases/latest)
