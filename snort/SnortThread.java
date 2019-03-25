package net.floodlightcontroller.snort;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;

import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4AddressWithMask;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.TransportPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.MappingJsonFactory;

import net.floodlightcontroller.firewall.FirewallRule;
import net.floodlightcontroller.firewall.IFirewallService;
import net.floodlightcontroller.firewall.FirewallRule.FirewallAction;

public class SnortThread extends Thread {

	protected IFirewallService firewall = null;
	protected Logger logger = null;
	protected static int count=1;// 记录连接了几个snort
	public SnortThread(IFirewallService firewall){
		this.firewall = firewall;
		logger = LoggerFactory.getLogger(SnortThread.class);
	}
	
	@Override
	public void run() {
		ServerSocket server = null;
		Socket s = null;
		try {
			server = new ServerSocket(51234);
			// 支持多个snort连接
			while(true){
				logger.info("Waiting for No." + count + " snort's connect");
				s = server.accept();
				logger.info("No."+count+" snort connected");
				// 新建一个线程来针对某一个snort进行通信
				new ServerThread(s,firewall).start();
				count++;
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}

class ServerThread extends Thread{
	private Socket s;
	private IFirewallService firewall;
	
	public ServerThread(Socket s, IFirewallService firewall){
		this.s = s;
		this.firewall = firewall;
	}

	@Override
	public void run() {
		InputStream inputStream = null;
		InputStreamReader reader = null;
		BufferedReader bufferedReader = null;
		try {
			inputStream = s.getInputStream();
			reader = new InputStreamReader(inputStream);
			bufferedReader = new BufferedReader(reader);
			String info = null;
			// 读取警告消息并解析成防火墙规则，然后添加
			while((info=bufferedReader.readLine())!=null){
				FirewallRule rule = jsonToFirewallRule(info);
				firewall.addRule(rule);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	private FirewallRule jsonToFirewallRule(String fmJson) {
		FirewallRule rule = new FirewallRule();
		MappingJsonFactory f = new MappingJsonFactory();
		JsonParser jp;
		try {
			try {
				jp = f.createParser(fmJson);
			} catch (JsonParseException e) {
				throw new IOException(e);
			}

			jp.nextToken();
			if (jp.getCurrentToken() != JsonToken.START_OBJECT) {
				throw new IOException("Expected START_OBJECT");
			}

			while (jp.nextToken() != JsonToken.END_OBJECT) {
				if (jp.getCurrentToken() != JsonToken.FIELD_NAME) {
					throw new IOException("Expected FIELD_NAME");
				}

				String n = jp.getCurrentName();
				jp.nextToken();
				if (jp.getText().equals("")) {
					continue;
				}


				else if (n.equalsIgnoreCase("src-mac")) {
					if (!jp.getText().equalsIgnoreCase("ANY")) {
						rule.any_dl_src = false;
						try {
							rule.dl_src = MacAddress.of(jp.getText());
						} catch (IllegalArgumentException e) {
						}
					}
				}

				else if (n.equalsIgnoreCase("dst-mac")) {
					if (!jp.getText().equalsIgnoreCase("ANY")) {
						rule.any_dl_dst = false;
						try {
							rule.dl_dst = MacAddress.of(jp.getText());
						} catch (IllegalArgumentException e) {
						}
					}
				}

				else if (n.equalsIgnoreCase("dl-type")) {
					if (jp.getText().equalsIgnoreCase("ARP")) {
						rule.any_dl_type = false;
						rule.dl_type = EthType.ARP;
					} else if (jp.getText().equalsIgnoreCase("IPv4")) {
						rule.any_dl_type = false;
						rule.dl_type = EthType.IPv4;
					}
				}

				else if (n.equalsIgnoreCase("src-ip")) {
					if (!jp.getText().equalsIgnoreCase("ANY")) {
						rule.any_nw_src = false;
						if (rule.dl_type.equals(EthType.NONE)){
							rule.any_dl_type = false;
							rule.dl_type = EthType.IPv4;
						}
						try {
							rule.nw_src_prefix_and_mask = IPv4AddressWithMask.of(jp.getText());
						} catch (IllegalArgumentException e) {
							//TODO should return some error message via HTTP message
						}
					}
				}

				else if (n.equalsIgnoreCase("dst-ip")) {
					if (!jp.getText().equalsIgnoreCase("ANY")) {
						rule.any_nw_dst = false;
						if (rule.dl_type.equals(EthType.NONE)){
							rule.any_dl_type = false;
							rule.dl_type = EthType.IPv4;
						}
						try {
							rule.nw_dst_prefix_and_mask = IPv4AddressWithMask.of(jp.getText());
						} catch (IllegalArgumentException e) {
						}
					}
				}

				else if (n.equalsIgnoreCase("nw-proto")) {
					if (jp.getText().equalsIgnoreCase("TCP")) {
						rule.any_nw_proto = false;
						rule.nw_proto = IpProtocol.TCP;
						rule.any_dl_type = false;
						rule.dl_type = EthType.IPv4;
					} else if (jp.getText().equalsIgnoreCase("UDP")) {
						rule.any_nw_proto = false;
						rule.nw_proto = IpProtocol.UDP;
						rule.any_dl_type = false;
						rule.dl_type = EthType.IPv4;
					} else if (jp.getText().equalsIgnoreCase("ICMP")) {
						rule.any_nw_proto = false;
						rule.nw_proto = IpProtocol.ICMP;
						rule.any_dl_type = false;
						rule.dl_type = EthType.IPv4;
					}
				}

				else if (n.equalsIgnoreCase("tp-src")) {
					rule.any_tp_src = false;
					try {
						rule.tp_src = TransportPort.of(Integer.parseInt(jp.getText()));
					} catch (IllegalArgumentException e) {
						//TODO should return some error message via HTTP message
					}
				}

				else if (n.equalsIgnoreCase("tp-dst")) {
					rule.any_tp_dst = false;
					try {
						rule.tp_dst = TransportPort.of(Integer.parseInt(jp.getText()));
					} catch (IllegalArgumentException e) {
						//TODO should return some error message via HTTP message
					}
				}

				else if (n.equalsIgnoreCase("priority")) {
					try {
						rule.priority = Integer.parseInt(jp.getText());
					} catch (IllegalArgumentException e) {
						//TODO should return some error message via HTTP message
					}
				}

			}
		} catch (IOException e) {
		}
		rule.ruleid=rule.genID();
		rule.action = FirewallAction.DROP;
		return rule;
	}
}
