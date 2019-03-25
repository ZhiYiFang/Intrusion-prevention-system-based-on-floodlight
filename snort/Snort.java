package net.floodlightcontroller.snort;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.firewall.FirewallRule;
import net.floodlightcontroller.firewall.IFirewallService;
import net.floodlightcontroller.firewall.FirewallRule.FirewallAction;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.snort.web.SnortWebRoutable;

public class Snort implements IFloodlightModule{

	// 本模块依赖的模块
	protected IFirewallService firewall;// 需要添加防火墙规则
	protected IRestApiService restApi;// 需要对外提供RESTful API
	
	// 本模块不对外提供服务，不用填写这个模块提供的服务
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		return null;
	}

	// 本模块对外不提供服务，因此也没有实现什么服务接口，不需要填写
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		return null;
	}

	// 填写依赖的模块
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<>();
		l.add(IFirewallService.class);
		l.add(IRestApiService.class);
		return l;
	}

	// 通过context将依赖的模块初始化
	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		firewall = context.getServiceImpl(IFirewallService.class);
		restApi = context.getServiceImpl(IRestApiService.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		// 注册本模块的RESTful API
		restApi.addRestletRoutable(new SnortWebRoutable());
		// 打开防火墙模块
		if(!firewall.isEnabled()){
			firewall.enableFirewall(true);
			// 添加一条允许通过的规则
			FirewallRule rule = new FirewallRule();
			rule.priority=2;
			rule.action = FirewallAction.ALLOW;
			rule.ruleid=rule.genID();
			firewall.addRule(rule);
		}
		// 如果采用socket通信就加上下边的代码
//		SnortThread snortThread = new SnortThread(firewall);
//		snortThread.start();
	}

}
