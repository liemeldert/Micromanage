import {auth} from "./auth";
import Tenant from "../models/tenant";

export default auth(async (req) => {
    const { pathname } = req.nextUrl;
    const tenantId = pathname.split('/')[1];

    if (!req.auth) {
        if (pathname !== "/auth/login") {
            const newUrl = new URL("/auth/login", req.nextUrl.origin);
            return Response.redirect(newUrl);
        }
    } else {
        const userId = req.auth.user?.id;
        if (!userId) {
            return new Response("Unauthorized", { status: 401 });
        }
        const tenant = await Tenant.findById(tenantId).exec();

        if (!tenant || !tenant.members.includes(userId)) {
            return new Response("Unauthorized", { status: 401 });
        }
    }
});