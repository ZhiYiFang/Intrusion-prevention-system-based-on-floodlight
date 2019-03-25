package net.floodlightcontroller.snort.web;

import java.io.IOException;

import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4AddressWithMask;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.TransportPort;
import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.MappingJsonFactory;

import net.floodlightcontroller.firewall.FirewallRule;
import net.floodlightcontroller.firewall.FirewallRule.FirewallAction;
import net.floodlightcontroller.firewall.IFirewallService;

public class AlertResource extends ServerResource{

	public static int id=0;
	static Logger log = LoggerFactory.getLogger(AlertResource.class);
	@Post
	public String addRule(String json){
		log.info("Get Alert Info from Snort");
		IFirewallService firewall = (IFirewallService)getContext().getAttributes().get(IFirewallService.class.getCanonicalName());
		FirewallRule rule = jsonToFirewallRule(json, id++);
		firewall.addRule(rule);
		return "{\"status\":\"success\"}";
	}
	public static FirewallRule jsonToFirewallRule(String fmJson,int id) {
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
		rule.ruleid=id;
		rule.action = FirewallAction.DROP;
		return rule;
	}
}
