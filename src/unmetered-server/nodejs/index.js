
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


const net = require("net");
const app = net.createServer();

const PORT = process.env.PORT || 8080;

app.on("connection", (clientToProxySocket) => {
  console.log("Client connected to Proxy");

  clientToProxySocket.once("data", (data) => {
    console.log(data.toString());
    let isConnectionTLS = data.toString().indexOf("CONNECT") !== -1;

    let serverPort = 80;
    let serverAddr;

    if (isConnectionTLS) {
      serverPort = 443;

      serverAddr = data
        .toString()
        .split("CONNECT ")[1]
        .split(":")[0];
        console.log("address: ",serverAddr);
    } else {
      serverAddr = data.toString().split("Host: ")[1].split("\r\n")[0];
    }
    let proxyToServerSocket = net.createConnection(
      {
        host: serverAddr,
        port: serverPort,
      },
      () => {
        console.log("Proxy connected to server");
      }
    );

    if (isConnectionTLS) {
      clientToProxySocket.write("HTTP/1.1 200 OK\r\n\r\n");
    } else {
      proxyToServerSocket.write(data);
    }

    clientToProxySocket.pipe(proxyToServerSocket);
    proxyToServerSocket.pipe(clientToProxySocket);

    proxyToServerSocket.on("error", (err) => {
      console.log("Proxy to server error");
      console.log(err);
    });

    clientToProxySocket.on("error", (err) => {
      console.log("Client to proxy error");
    });

    app.once("close", () => {//app.once instead of on because of memory leak warning
      console.log("Connection closed");
    });
  });
});


app.listen({ port: PORT }, () => {
  console.log("Server running on PORT:", PORT);
});




