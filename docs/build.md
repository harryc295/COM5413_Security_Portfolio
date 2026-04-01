 # Build Log – The Benji Protocol
 
## Week 1 – The Scene (`log_parser.py`)

- built a log parser than extracts failed auth attempts from auth.log and also uses regex to match failed password and invalid user attempts.
- used md5 hash of timestamp + ip + user to make sure duplicates dont occur
- can output csv file with timestamp ip and user account
- handles files and has a set file limit

  ##what broke
    
  - regex orginally didnt work at all

  ## how i fixed it
  i added multiple patterns to cover all like diffrent types of failed authetnication


  ## Week 2 – The Map (`scan.py`)

  -built a tcp port scanner
  -grabs service banner and recives data from open sockets
  -parses port specifications e.g. from 1-1024 or lists 21,22,80
  -outputs to json and saves

  ## what broke
  -hostname resolution didnt work orginally and would just crash

  ## how i fixed it
  -added a resolve target method that catches socket.gaierror

  ## Week 3 – The Key (`brute.py`)

   -built a bruteforcer / tester for ssh (paramiko) and ftp (ftplib)
  - has the set 0.1 seccond delay
  - logs every attempt to a file
  - sucess message that was needed by the brief
 
    ## what broke

    -orginally struggled with non default ports

    ##how i fixed it

    - added --port arguments defaults to 22 for ssh and 21 for ftp

 
     ## Week 4 – The Surface (`web_enum.py`)

      -built a web enumerator using requests and beutiful soup
      - extracts server and xpowered by
      -  finds all html comments etc
      -  probes default paths e.g. robots and admin etc
      -  outputs plaintext and optional csv
   
     ##what broke

    the comment extraction was attempting to match text starting with a empty string so no comments

    ##how i fixed it

    used `soup.find_all(string=lambda s: isinstance(s, Comment))` to get real html comments
