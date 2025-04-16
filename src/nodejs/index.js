//send minimal data over a metered connection
//on the first time, send all code
//to parse the minimal data into HTML, so
//later less data is used

//list interfaces
  const nets = require("os").networkInterfaces();
  const results = Object.create(null); // Or just '{}', an empty object

  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      // Skip over non-IPv4 and internal (i.e. 127.0.0.1) addresses
      // 'IPv4' is in Node <= 17, from 18 it's a number 4 or 6
      const familyV4Value = typeof net.family === 'string' ? 'IPv4' : 4
      if (net.family === familyV4Value && !net.internal) {
        if (!results[name]) {
          results[name] = [];
        }
        results[name].push(net.address);
      }
    }
  }
  console.log("Possible Private IPs:\n", results);
var tld = [];
// get cached TLDs
  const buffer
    = require('fs').readFileSync(
        require('path').join(__dirname, '../tld')
      );
  
  for(const byte of buffer){
    const char = String.fromCharCode(byte);
    if(!tld.length){
      if(byte === 0x0A) tld.push("");//wait until newline to begin
    }else{
      if((byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A) || (byte >= 0x30 && byte <= 0x39) || (byte === 0x2D)){
     // ( ((   UPPER LATIN LETTER   ))  ||  ((   LOWER LATIN LETTER   ))  ||  ((   NUMBERS  /  DIGITS   ))  ||  (   MINUS   ) )
        tld[tld.length - 1] += char;
      }else if(byte === 0x0D){
        //////////////////////
      }else if(byte === 0x0A){
        tld.push("")
      }else{
        throw("nonothrow");
      }
    }
  }


const net = require("net");
const app = net.createServer();

const PORT = process.env.PORT || 8080;
///////////////////////////||
var allowLocals = false; //||    allow underdashed hostnames and custom tlds (and in turn, likely, allow internal access), including localhost tld, and allow certain IPs ([::], [::1], 0.0.0.0, 127.X.X.X) )
///////////////////////////||    to be implemented: modify to be specific to clients with creds, block [::] and [::1] but need to figure out how to normalize them to whole IPv6
app.on("connection", proxyClient => {
  console.log("Someone connected to the Proxy!");

  proxyClient.once("data", data => {//to be implemented: broken packets
    var method = "";
    var host = [""];
      var zeroGroupUsed = false;
     var hostlength = 0;
    var port = "";
    var path = "";
    var httpv = "";
    var headers = [[]];
    var requestLine = "";
    var tokening = ["method"];
    for(const addr in data){
      const byte = data[addr];
      const strb = String.fromCharCode(byte);
      requestLine += strb;
      switch(tokening[0]){
        case "method"://to be implemented: nonstandard methods
          if ((byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A)) {
            // ( ((   UPPER LATIN LETTER   ))  ||  ((   LOWER LATIN LETTER   )) )
            method += strb.toUpperCase();
            var methodValid = false;
            for( const m of "CONNECT,GET,HEAD,POST,PUT,DELETE,PATCH,OPTIONS,TRACE".split(",") ){
              if(m.startsWith(method)){ methodValid = true; break }
            }
            if(!methodValid){//method is invalid. also catches long methods (which are also invalid)
              console.warn(`ERR: UNSUPPORTED_METHOD recieved from "${proxyClient.remoteAddress}"; Expected a valid HTTP Method but began reading "${method}"`);
              proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: UNSUPPORTED_METHOD");
              return proxyClient.end();
            }
          }else{//assume method is done
            if(byte !== 0x20){
              console.warn(`ERR: BAD_DELIMITER from "${proxyClient.remoteAddress}"; Expected space (ASCII 0x20) but got "${strb}"`);
              proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: BAD_DELIMITER");
              return proxyClient.end();
            }
            var methodValid = "CONNECT,GET,HEAD,POST,PUT,DELETE,PATCH,OPTIONS,TRACE".split(",").includes(method);
            if(!methodValid){//
              console.warn(`ERR: UNSUPPORTED_METHOD recieved from "${proxyClient.remoteAddress}"; Expected a complete, valid HTTP Method but ended prematurely with "${method}"`);
              proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: UNSUPPORTED_METHOD");
              return proxyClient.end();
            }
            //passed all checks, move on to url
            tokening = ["url","host"];
          }
          break;
        case "url":
          switch(tokening[1]){
            case "host":
              if(host[0] === "["){//handle IPv6 separately
                if("0123456789ABCDEFabcdef".split("").includes(strb)){
                  if(host.length === 3 && host[1] === ""){//currently ["[", "", ""], meaning a colon went first, then hex. no point on checking host[2] since this line stops any further altering of it. should never be ["[","","ABCD"....]
                    console.warn(`ERR: INVALID_IPv6 recieved from "${proxyClient.remoteAddress}"; A leading singular-colon was found, which is not allowed`);
                    proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: INVALID_IPv6");
                    return proxyClient.end();
                  }else if(host[host.length-1].length === 4){//invalid IPv6
                    console.warn(`ERR: INVALID_IPv6 recieved from "${proxyClient.remoteAddress}"; IPv6 label too long, more than 4 hex digits`);
                    proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: INVALID_IPv6");
                    return proxyClient.end();
                  }else{//valid
                    host[host.length-1] += strb;
                  }
                }else if(strb === ":"){
                  if(host.length === 5 && !zeroGroupUsed){//currently ["[","0123","4567","89AB","CDEF"], going to 6 is too long: [0123:4567:89AB:CDEF(:X)]
                    console.warn(`ERR: INVALID_IPv6 recieved from "${proxyClient.remoteAddress}"; IPv6 too long, more than 4 labels`);
                    proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: INVALID_IPv6");
                    return proxyClient.end();
                  }else if(host.length === 6 && zeroGroupUsed)// currently ["[",("","",)"4567",("","",)"89AB",("","",)"CDEF"(,"","")], going to 7 is too long: [::4567:89AB:CDEF(:X)], [0123::89AB:CDEF(:X)], [0123:4567::CDEF(:X)], [0123::89AB:CDEF(:X)],
                  if(host[host.length-1] === ""){//double colon
                    if(!zeroGroupUsed){//prevent more than one instance of a double colon, as well as triple colons
                      console.warn(`ERR: NON_STANDARD_IPv6 recieved from "${proxyClient.remoteAddress}"; found more than one instance of two consecutive colons, which are not allowed`);
                      proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: INVALID_IPv6");
                      return proxyClient.end();
                    }else{
                      host.push("")
                    }
                  }else{
                    host.push("");
                  }
                }else if(strb == "]"){
                  if(host[host.length-1] === ""){//ended with colon
                    if(host[host.length-2] !== ""){//ended with single colon, not allowed
                      console.warn(`ERR: INVALID_IPv6 recieved from "${proxyClient.remoteAddress}";  A leading singular-colon was found, which is not allowed`);
                      proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: INVALID_IPv6");
                      return proxyClient.end();
                    }else{//otherwise ended in double colon
                      host.push(strb);
                      tokening = ["port"]
                    }
                  }else{//ended on hex
                    host.push(strb);
                    tokening = ["port"]
                  }
                }
              }else if(strb === "[" && host[0].length === 1 && host[0] === ""){//allow HOSTNAME_HAS_ILLEGAL_CHARACTER to handle a (host !== [""]). if not, init as IPv6
                host[0] = "[";
                host.push("");
              }else if(strb === "."){
                if(host[host.length-1] == ""){//if double dotted
                  console.warn(`ERR: EMPTY_HOSTNAME_LABEL recieved from "${proxyClient.remoteAddress}"; expected another label but got "."`);
                  proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: UNSUPPORTED_HOSTNAME");
                  return proxyClient.end();
                }else if(host[host.length-1].endsWith("-")){//check for ending dash
                  console.warn(`ERR: HOSTNAME_LABEL_END_IN_DASH recieved from "${proxyClient.remoteAddress}"; expected completion of label but got "."`);
                  proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: UNSUPPORTED_HOSTNAME");
                  return proxyClient.end();
                }else if(host[host.length-1].length == 63){//check label length
                  console.warn(`ERR: HOSTNAME_LABEL_TOO_LONG recieved from "${proxyClient.remoteAddress}"; expected port-delimiting colon but got another letter`);
                  proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: UNSUPPORTED_HOSTNAME");
                  return proxyClient.end();
                }else if(hostlength === 255){//check whole length
                  console.warn(`ERR: HOSTNAME_TOO_LONG recieved from "${proxyClient.remoteAddress}"; expected a maximum of 255 bytes for a hostname but exceeded`);
                  proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: UNSUPPORTED_HOSTNAME");
                  return proxyClient.end();
                }else{//continue to next label
                  host.push("");
                  hostlength++;
                }
              }else if((byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A) || (byte >= 0x30 && byte <= 0x39)){
                   // ( ((   UPPER LATIN LETTER   ))  ||  ((   LOWER LATIN LETTER   ))  ||  ((   NUMBERS  /  DIGITS   )) )
                if(host[host.length-1].length == 63){//check label length
                  console.warn(`ERR: HOSTNAME_LABEL_TOO_LONG recieved from "${proxyClient.remoteAddress}"; expected port-delimiting colon but got another letter`);
                  proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: UNSUPPORTED_HOSTNAME");
                  return proxyClient.end();
                }else if(hostlength === 255){//check whole length
                  console.warn(`ERR: HOSTNAME_TOO_LONG recieved from "${proxyClient.remoteAddress}"; expected a maximum of 255 bytes for a hostname but exceeded`);
                  proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: UNSUPPORTED_HOSTNAME");
                  return proxyClient.end();
                }else{
                  host[host.length-1] += strb;
                  hostlength++;
                }
              }else if(strb === "-"){
                if(host[host.length-1] === ""){//if empty label, therefore label has beginning dash
                  console.warn(`ERR: HOSTNAME_LABEL_BEGIN_IN_DASH recieved from "${proxyClient.remoteAddress}"; expected letter or number but got "-"`);
                  proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: UNSUPPORTED_HOSTNAME");
                  return proxyClient.end();
                }else if(host[host.length-1].length == 63){//check label length
                  console.warn(`ERR: HOSTNAME_LABEL_TOO_LONG recieved from "${proxyClient.remoteAddress}"; expected port-delimiting colon but got another letter`);
                  proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: UNSUPPORTED_HOSTNAME");
                  return proxyClient.end();
                }else if(hostlength === 255){//check whole length
                  console.warn(`ERR: HOSTNAME_TOO_LONG recieved from "${proxyClient.remoteAddress}"; expected a maximum of 255 bytes for a hostname but exceeded`);
                  proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: UNSUPPORTED_HOSTNAME");
                  return proxyClient.end();
                }else{
                  host[host.length-1] += strb;
                  hostlength++;
                }
              }else if(strb === "_"){
                if(allowLocals){
                  if(host[host.length-1].length == 63){//check label length
                    console.warn(`ERR: HOSTNAME_LABEL_TOO_LONG recieved from "${proxyClient.remoteAddress}"; expected port-delimiting colon but got another letter`);
                    proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: UNSUPPORTED_HOSTNAME");
                    return proxyClient.end();
                  }else if(hostlength === 255){//check whole length
                    console.warn(`ERR: HOSTNAME_TOO_LONG recieved from "${proxyClient.remoteAddress}"; expected a maximum of 255 bytes for a hostname but exceeded`);
                    proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: UNSUPPORTED_HOSTNAME");
                    return proxyClient.end();
                  }else{
                    host[host.length-1] += strb;
                    hostlength++;
                  }
                }else{
                  console.warn(`ERR: UNPRIVILEDGED_LOCAL_ACCESS recieved from "${proxyClient.remoteAddress}"; expected letter, number, dash, or period, but got an underdash, in attempt to access a locally hosted platform`);
                  proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: UNSUPPORTED_HOSTNAME");
                  return proxyClient.end();
                }
              }else if(strb === ":"){
                if(host[host.length-1] == ""){//check if "." before ":"
                  console.warn(`ERR: EMPTY_HOSTNAME_LABEL recieved from "${proxyClient.remoteAddress}"; expected another label but got "."`);
                  proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: UNSUPPORTED_HOSTNAME");
                  return proxyClient.end();
                }else if(host[host.length-1].endsWith("-")){//check if "-" before ":", if ending in dash
                  console.warn(`ERR: HOSTNAME_LABEL_END_IN_DASH recieved from "${proxyClient.remoteAddress}"; expected completion of label but got "."`);
                  proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: UNSUPPORTED_HOSTNAME");
                  return proxyClient.end();
                }else{
                  if(!allowLocals){
                    if(
                      host.length === 4 
                        && 
                      host.reduce(
                        (acc,add)=>(
                          acc && (((/^\d{1,3}$/.test(add))?parseInt(add):256) < 256)
                        ),
                        true
                      ) 
                    ){//if IP
                      if(host[0] === "0" && host[1] === "0" && host[2] === "0" && host[3] === "0"){
                        console.warn(`ERR: UNPRIVILEDGED_LOCAL_ACCESS recieved from "${proxyClient.remoteAddress}"; 0.0.0.0 is restricted`);
                        proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: UNSUPPORTED_HOSTNAME");
                        return proxyClient.end();
                      }else if(host[0] === "127"){
                        console.warn(`ERR: UNPRIVILEDGED_LOCAL_ACCESS recieved from "${proxyClient.remoteAddress}"; 127.X.X.X is restricted`);
                        proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: UNSUPPORTED_HOSTNAME");
                        return proxyClient.end();
                      }else if(host[0] === "10"){
                        console.warn(`ERR: UNPRIVILEDGED_LOCAL_ACCESS recieved from "${proxyClient.remoteAddress}"; 10.X.X.X is restricted`);
                        proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: UNSUPPORTED_HOSTNAME");
                      }else if(host[0] === "192" && host[1] === "168"){
                        console.warn(`ERR: UNPRIVILEDGED_LOCAL_ACCESS recieved from "${proxyClient.remoteAddress}"; 192.168.X.X is restricted`);
                        proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: UNSUPPORTED_HOSTNAME");
                      }else if(host[0] === "172" && host[1] >= 16 && host[1] <= 31){
                        console.warn(`ERR: UNPRIVILEDGED_LOCAL_ACCESS recieved from "${proxyClient.remoteAddress}"; 172.[16...31].X.X is restricted`);
                        proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: UNSUPPORTED_HOSTNAME");
                      }else if(host[0] >= 224 && host[0] <= 239){//go on
                        console.warn(`ERR: UNPRIVILEDGED_LOCAL_ACCESS recieved from "${proxyClient.remoteAddress}"; [224...239].X.X.X is restricted`);
                        proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: UNSUPPORTED_HOSTNAME");
                      }else{
                        tokening[1] = "port";
                      }
                    }else if(!tld.includes(host[host.length-1].toUpperCase())){ //not an IP, if TLD not publicly recognized:
                      console.warn(`ERR: UNSUPPORTED_HOSTNAME recieved from "${proxyClient.remoteAddress}"; TLD isn't recognized: "${host[host.length-1]}"`);
                      proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: UNSUPPORTED_HOSTNAME");
                      return proxyClient.end();
                    }else{//go on
                      tokening[1] = "port";
                    }
                  }else{//who cares
                    tokening[1] = "port";
                  }
                }
              }else if(strb === " "){
                console.warn(`ERR: PREMATURE_DELIMITER recieved from "${proxyClient.remoteAddress}"; expected more information but recieved ending marker (SPACE, " ", 0x20) for url`);
                proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: UNSUPPORTED_URL");
                return proxyClient.end();
              }else if(strb === "/"){
                if(host[0] === ""){//<METHOD> (???)/<pathname> <httpv>
                  console.warn(`ERR: PROXY_CLIENTS_ONLY recieved from "${proxyClient.remoteAddress}"; recieved a move to a pathname (SOLIDUS, "/", 0x2F) from the beginning, but only HTTP servers handle that!`);
                  proxyClient.write("HTTP/1.1 418 I'm a proxy\n\nI'm a proxy!");
                  return proxyClient.end();
                }else{
                  console.warn(`ERR: PORT_REQUIRED recieved from "${proxyClient.remoteAddress}"; recieved a move to a pathname (SOLIDUS, "/", 0x2F) instead of a port, but proxies require ports`);
                  proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: PORT_REQUIRED");
                  return proxyClient.end();
                }
              }else{
                console.warn(`ERR: HOSTNAME_HAS_ILLEGAL_CHARACTER recieved from "${proxyClient.remoteAddress}"; expected letter, number, dash, or period, but got an unhandleable character`);
                proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: UNSUPPORTED_HOSTNAME");
                return proxyClient.end();
              }
              
              break;
            case "port":
              if((byte >= 0x30 && byte <= 0x39)){
                if((port === "") && (strb === "0")){//though allowed by specs, can open room for unlimited zeroes, and in hand crashes. to be implemented proper handling
                  console.warn(`ERR: PORT_PADDED recieved from "${proxyClient.remoteAddress}"; expected beginning number of 1-9, but got 0`);
                  proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: PORT_ILLEGAL");
                  return proxyClient.end();
                }else if(parseInt(port+=strb) > 65535){// highest 65535
                  console.warn(`ERR: PORT_TOO_LARGE recieved from "${proxyClient.remoteAddress}"; port doesnt exist, expected port below 65536`);
                  proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: PORT_ILLEGAL");
                  return proxyClient.end();
                }
              }else if(strb === "/"){
                port = parseInt(port);
                tokening[1] = "path";
              }else if(strb === " "){
                if(method === "CONNECT"){//CONNECT abc.xyz:123 HTTP/1.1
                  tokening = ["httpv"];
                }else{
                  console.warn(`ERR: PREMATURE_DELIMITER recieved from "${proxyClient.remoteAddress}"; expected more information but recieved ending marker (SPACE, " ", 0x20) for url`);
                  proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: UNSUPPORTED_URL");
                  return proxyClient.end();
                }
              }else{
                console.warn(`ERR: PORT_HAS_ILLEGAL_CHARACTER recieved from "${proxyClient.remoteAddress}"; expected a number, but got an unhandleable character`);
                proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: PORT_ILLEGAL");
                return proxyClient.end();
              }
              break;
            case "path":
              if("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/?:@!$&'()*+,;=%".split("").includes(strb)){//i dont care how it looks, pass it on to the receiving server. as long as it's one of these, it's correct in my book
                if(path.length === 10000){
                  console.warn(`ERR: PATH_TOO_LONG recieved from "${proxyClient.remoteAddress}"; expected a path shorter than 10k chars, but exceeded`);
                  proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: PATH_LONG");
                  return proxyClient.end();
                }else{
                  path += strb
                }
              }else if(strb === " "){
                tokening = ["httpv"];
              }else{
                console.warn(`ERR: PATH_HAS_ILLEGAL_CHARACTER recieved from "${proxyClient.remoteAddress}"; expected a valid path character , but got an unhandleable character`);
                proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: PATH_ILLEGAL");
                return proxyClient.end();
              }
              break;
          }
          break;
        case "httpv":
          httpv+=strb;
          if("HTTP/1.1".startsWith(httpv)){//["H","HT","HTT","HTTP","HTTP", "HTTP/"].includes(httpv)
            //only version supporting persistent connections over Text. (because HTTP)
            //previous version is outdated HTTP/1.1 and next version is only (mainly) available via TLS, and in binary format. 
            // couldn't handle HTTP/2 anyway, and HTTP/1 too old.
            //do nothing
          }else if(httpv === "HTTP/1.1\r"){
            //see what they're doing
          }else if(["HTTP/1.1\r\n","HTTP/1.1\n"].includes(httpv)){
            httpv = "HTTP/1.1";
            tokening = ["headers"];
          }else if(httpv === "HTTP/1.1 "){
            console.warn(`ERR: INAPPROPRIATE_DELIMITER recieved from "${proxyClient.remoteAddress}"; didn't expect more information on the same line`);
            proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: PURPOSES_UNKNOWN");
            return proxyClient.end();//"What am i supposed to do with this?"
          }else{
            console.warn(`ERR: HTTP_VERSION_UNSUPPORTED_OR_ILLEGAL recieved from "${proxyClient.remoteAddress}"; expected a HTTP/1.1 , but got something else`,`\nStopped at: "${requestLine}"\n`,{method,host,port,path,httpv});
            proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: UNSUPPORTED_HTTP_VER");
            return proxyClient.end();
          }
          break;
        case "headers":
          switch(strb){
            case  ":":
              switch(headers[headers.length-1].length){
                case 0:// colon at beginning of line
                  console.warn(`ERR: INAPPROPRIATE_DELIMITER recieved from "${proxyClient.remoteAddress}"; expected a header name, but went straight to value`);
                  proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: PURPOSES_UNKNOWN");
                  return proxyClient.end();
                  break;
                case 1:// go on
                headers[headers.length-1].push("");
                  break;
                case 2://too many colons, only one (two sections) allowed, attempting to add another
                  console.warn(`ERR: INAPPROPRIATE_DELIMITER recieved from "${proxyClient.remoteAddress}"; expexted a key and value pair of a header, but got a mysterious third value`);
                  proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: PURPOSES_UNKNOWN");
                  return proxyClient.end();
                  break;
              }
              break;
            case  " ":
              switch(headers[headers.length-1].length){
                case 0:// currently " (idek what to do with this)"         line starts on space
                  console.warn(`ERR: INAPPROPRIATE_DELIMITER recieved from "${proxyClient.remoteAddress}"; expected a header name, but header line began on space?????`);
                  proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: PURPOSES UNKNOWN");
                  break;
                case 1://currently "HEADER (NAME: VALUE)" or "HEADER_NAME (:VALUE)", space within header name or space before colon.
                  console.warn(`ERR: INAPPROPRIATE_DELIMITER recieved from "${proxyClient.remoteAddress}"; expected a valid header name, but appears to contain a space or is terminated with padded space before a colon`);
                  proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: PURPOSES_UNKNOWN");
                  break;
                case 2:
                  if(headers[headers.length-1][1] === ""){//currently "HEADER-NAME: " or "HEADER-NAME:  " or so on.
                    //skip spaces after colon
                  }else{//currently "HEADER-NAME: X " or "HEADER-NAME: YD E " or similar
                    headers[headers.length-1][1] += " ";
                  }
                  break;
              }
            case "\r":
              //ignore, \n likely next
              break;
            case "\n":
              switch(headers[headers.length-1].length){
                case 0:// empty line, making another empty line, indicating end of headers
                  tokening = ['body'];
                  break;
                case 1://is (was)still setting the header name, but attempting to prematurely end the line;
                  console.warn(`ERR: INAPPROPRIATE_DELIMITER recieved from "${proxyClient.remoteAddress}"; expected a header name and value, but terminated line before getting to the value!`);
                  proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: PURPOSES_UNKNOWN");
                  break;
                case 2:
                  if(headers[headers.length-1][1].length){//if value has content
                    headers.push([]);
                  }else{
                    console.warn(`ERR: INAPPROPRIATE_DELIMITER recieved from "${proxyClient.remoteAddress}"; got an empty header! Don't know what that's about...`)
                    proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: PURPOSES_UNKNOWN");
                  }
                  break;
              }
              break;
            default:
              switch(headers[headers.length-1].length){
                case 0:// begin header name
                  headers[headers.length-1].push("");
                case 1://add to header name
                  if("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~!#$&'()*+,/:;=?@[]".split("").includes(strb)){
                    headers[headers.length-1][0] += strb;
                  }else{
                    console.warn(`ERR: HEADER_NAME_HAS_ILLEGAL_CHARACTER recieved from "${proxyClient.remoteAddress}"; expected a valid header name character , but got an unhandleable character`);
                    proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: HEADER_ILLEGAL");
                  }
                  break;
                case 2://add to header value
                  if("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~!#$&'()*+,/:;=?@[]".split("").includes(strb)){// https://stackoverflow.com/questions/47687379/what-characters-are-allowed-in-http-header-values
                    headers[headers.length-1][1] += strb;
                  }else{
                    console.warn(`ERR: HEADER_VALUE_HAS_ILLEGAL_CHARACTER recieved from "${proxyClient.remoteAddress}"; expected a valid header value character , but got an unhandleable character`);
                    proxyClient.write("HTTP/1.1 400 Bad Request\n\nERR: HEADER_ILLEGAL");
                  }
                  break;
              }
              break;
          }
          break;
        case "body":
          break;
      }
    }
  });
  proxyClient.on("error", (err) => {
    console.log(`Error communicating with "${proxyClient.remoteAddress}", `+err.message);
  });

  proxyClient.once("close", () => {//app.once instead of on because of memory leak warning
    console.log(`Connection closed with "${proxyClient.remoteAddress}"`);
  });
});


app.listen({ port: PORT }, () => {
  console.log("Server running on PORT:", PORT);
});