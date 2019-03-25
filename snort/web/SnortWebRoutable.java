package net.floodlightcontroller.snort.web;

import org.restlet.Context;
import org.restlet.Restlet;
import org.restlet.routing.Router;

import net.floodlightcontroller.restserver.RestletRoutable;

public class SnortWebRoutable implements RestletRoutable{
	// 将相应的资源类与URL关联
	@Override
	public Restlet getRestlet(Context context) {
		Router router = new Router(context);
		router.attach("/alerts/json",AlertResource.class);
		return router;
	}

	@Override
	public String basePath() {
		return "/wm/snort";
	}
}
