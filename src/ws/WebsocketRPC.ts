import uWS, {TemplatedApp} from "uWebSockets.js";
import ReconnectingWebSocket from "reconnecting-websocket";
import WebSocket from "ws";
import {TelosEvmConfig} from "../types";
import Subscription from "./Subscription";
import LogSubscription from "./LogSubscription";
import {createLogger} from "../util/logger";

const NEW_HEADS_SUBSCRIPTION = "0x9ce59a13059e417087c02d3236a0b1cd"
const logger = createLogger('telos-evm-rpc-ws');

export default class WebsocketRPC {

    config: TelosEvmConfig
    websocketRPC: TemplatedApp
    websocketClient: ReconnectingWebSocket
    rpcHandlerContainer: any
    logSubscriptions: Map<string, LogSubscription>
    headSubscription: Subscription


    constructor(config: TelosEvmConfig, rpcHandlerContainer: any) {
        console.log('Initializing Websocket...');
        this.config = config;
        this.initUWS();
        this.initWSClient();
        this.rpcHandlerContainer = rpcHandlerContainer;
        this.logSubscriptions = new Map();
        this.headSubscription = new Subscription(this.websocketRPC, NEW_HEADS_SUBSCRIPTION);
    }

    initWSClient(): void{
        this.websocketClient = new ReconnectingWebSocket(this.config.indexerWebsocketUri, [], {WebSocket});
        this.websocketClient.addEventListener('message', (data) => {
            this.handleIndexerMessage(data.data);
        })
    }

    initUWS(): void {
        const host = this.config.rpcWebsocketHost;
        const port = this.config.rpcWebsocketPort;
        let ip, origin;
        this.websocketRPC = uWS.App({}).ws('/evm', {
            compression: 0,
            maxPayloadLength: 16 * 1024 * 1024,
            idleTimeout: 30,
            upgrade: (res: uWS.HttpResponse, req: uWS.HttpRequest, context: uWS.us_socket_context_t) => {
                const tRef = process.hrtime.bigint();
                const buffer = Buffer.from(res.getRemoteAddressAsText());
                const string = buffer.toString();
                ip = req.getHeader('x-forwarded-for') || string || '';

                if (req.getHeader('origin') === 'chrome-extension://nkbihfbeogaeaoehlefnkodbefgpgknn') {
                    origin = 'MetaMask';
                } else {
                    if (req.getHeader('origin') && req.getHeader('origin').length > 0) {
                        origin = req.getHeader('origin');
                    } else {
                        origin = req.getHeader('user-agent');
                    }
                }

                res.upgrade(
                   { clientInfo: {ip, origin} },
                    req.getHeader('sec-websocket-key'),
                    req.getHeader('sec-websocket-protocol'),
                    req.getHeader('sec-websocket-extensions'),
                    context
                )

                const duration = ((Number(process.hrtime.bigint()) - Number(tRef)) / 1000).toFixed(3);
                console.log(`WSCONNECT:  ${new Date().toISOString()} - ${duration} μs - ${ip} (0/0) - ${origin} - connect`);
            },
            message: (ws: uWS.WebSocket, msg: ArrayBuffer) => {
                this.handleMessage(ws, msg, ip, origin);
            },
            drain: () => {
            },
            close: (ws: uWS.WebSocket) => {
                this.headSubscription.removeWs(ws, true);
                for (const [subId, sub] of this.logSubscriptions)
                    sub.removeWs(ws, true)
            },
        }).listen(host, port, (token: uWS.us_listen_socket) => {
            if (token) {
                console.log('Websocket listening to port ' + port);
            } else {
                console.log('Websocket failed to listen to port ' + port);
            }
        });
    }

    makeResponse(result, originalMessage) {
        return {"jsonrpc": "2.0", result, id: originalMessage.id};
    }

    makeError(message, id=null, code=-32600) {
        return {"jsonrpc": "2.0", "error": {code, message}, id};
    }

    async handleMessage(ws, msg, ip, origin) {
        const tRef = process.hrtime.bigint();
        const buffer = Buffer.from(msg);
        const string = buffer.toString();
        try {
            const msgObj = JSON.parse(string);
            if (!msgObj.method) {
                ws.send(this.makeError("Invalid Request, no method specified", msgObj.id ? msgObj.id : null));
                return;
            }
            const method = msgObj.method;
            if (method == "eth_subscribe") {
                this.handleSubscription(ws, msgObj);
                const duration = ((Number(process.hrtime.bigint()) - Number(tRef)) / 1000).toFixed(3);
                console.log(`WSSUBSCRIBE:  ${new Date().toISOString()} - ${duration} μs - ${ip} (0/0) - ${origin} - ${msgObj.params[0]}`);
                return;
            } else if (method === "eth_unsubscribe") {
                if (!msgObj?.params?.length) {
                    ws.send(JSON.stringify(this.makeError("Subscription ID should be provided as first parameter", msgObj.id)))
                    return;
                }
                const subscriptionId = msgObj.params[0];
                if (subscriptionId === NEW_HEADS_SUBSCRIPTION) {
                    this.headSubscription.removeWs(ws, false);
                } else {
                    this.logSubscriptions.forEach((sub) => {
                        if (sub.getId() === subscriptionId)
                            sub.removeWs(ws, false);

                        if (!sub.hasClients())
                            this.logSubscriptions.delete(sub.getId());
                    });
                }
                ws.send(JSON.stringify(this.makeResponse(true, msgObj)));
                const duration = ((Number(process.hrtime.bigint()) - Number(tRef)) / 1000).toFixed(3);
                console.log(`WSUNSUBSCRIBE:  ${new Date().toISOString()} - ${duration} μs - ${ip} (0/0) - ${origin} - ${msgObj.params[0]}`);
                return;
            } else if (method === "eth_unsubscribeAll") {
                this.headSubscription.removeWs(ws, false);
                this.logSubscriptions.forEach((sub) => {
                    sub.removeWs(ws, false);
                    if (!sub.hasClients())
                        this.logSubscriptions.delete(sub.getId());
                });
                ws.send(JSON.stringify(this.makeResponse(true, msgObj)));
                const duration = ((Number(process.hrtime.bigint()) - Number(tRef)) / 1000).toFixed(3);
                console.log(`WSUNSUBSCRIBE:  ${new Date().toISOString()} - ${duration} μs - ${ip} (0/0) - ${origin} - all`);
                return;
            }

            const rpcResponse = await this.rpcHandlerContainer.handler(msgObj, ws.clientInfo);
            ws.send(JSON.stringify(rpcResponse));
            const duration = ((Number(process.hrtime.bigint()) - Number(tRef)) / 1000).toFixed(3);
            console.log(`WS:  ${new Date().toISOString()} - ${duration} μs - ${ip} (0/0) - ${origin} - ${msgObj.method}`);
        } catch (e) {
            console.error(`Failed to parse websocket message: ${string} error: ${e.message}`);
        }
    }

    async handleSubscription(ws, msgObj): Promise<void> {
        switch (msgObj.params[0]) {
            case 'logs':
                this.handleLogSubscription(ws, msgObj);
                break;
            case 'newHeads':
                this.handleNewHeadsSubscription(ws, msgObj);
                break;
            default:
                ws.send(JSON.stringify(this.makeError(`Subscription type ${msgObj.params[0]} is not supported`, msgObj.id)));
                break;
        }
    }

    async handleLogSubscription(ws, msgObj): Promise<void> {
        const filter = msgObj.params[1];
        if(!filter?.address){
            ws.send(JSON.stringify(this.makeError("address should be provided in params", msgObj.id)));
        }
        const subscriptionId = LogSubscription.makeId(filter);
        if (!this.logSubscriptions.has(subscriptionId)) {
            this.logSubscriptions.set(subscriptionId, new LogSubscription(this.websocketRPC, subscriptionId, filter, this.config.debug))
        }

        this.logSubscriptions.get(subscriptionId).addWs(ws);
        ws.send(JSON.stringify(this.makeResponse(subscriptionId, msgObj)));
    }

    async handleNewHeadsSubscription(ws, msgObj): Promise<void> {
        this.headSubscription.addWs(ws);
        ws.send(JSON.stringify(this.makeResponse(this.headSubscription.getId(), msgObj)));
    }

    handleIndexerMessage(data): void{
        const dataObj = JSON.parse(data);
        if(dataObj.data?.stateRoot && dataObj.data?.stateRoot.startsWith('0x') === false){
           dataObj.data.stateRoot = '0x' + dataObj.data.stateRoot;
        }
        switch (dataObj.type) {
            case 'raw':
                this.handleRawMessage(dataObj.data);
                break;
            case 'head':
                this.handleHeadMessage(dataObj.data);
                break;
            default:
                break;
        }
    }

    handleRawMessage(data): void {
        for (const [subId, sub] of this.logSubscriptions) {
            const tRef = process.hrtime.bigint();
            sub.handleRawAction(data);
            const duration = ((Number(process.hrtime.bigint()) - Number(tRef)) / 1000).toFixed(3);
            for(let ws of  sub.wsClients){
                console.log(`WSPUBLISH:  ${new Date().toISOString()} - ${duration} μs - ${ws[0].clientInfo.ip} (0/0) - ${ws[0].clientInfo.origin} - raw`);
            }
        }
    }

    handleHeadMessage(head): void {
        const tRef = process.hrtime.bigint();
        if(this.headSubscription.hasClients()){
            const headMessage = {
                "jsonrpc": "2.0",
                "method": "eth_subscription",
                "params": {
                    "subscription": this.headSubscription.getId(),
                    "result": head
                }
            };
            this.headSubscription.publish(JSON.stringify(headMessage));
            const duration = ((Number(process.hrtime.bigint()) - Number(tRef)) / 1000).toFixed(3);
            for(let ws of this.headSubscription.wsClients){
                console.log(`WSPUBLISH:  ${new Date().toISOString()} - ${duration} μs - ${ws[0].clientInfo.ip} (0/0) - ${ws[0].clientInfo.origin} - newHeads`);
            }
        }
    }

}
