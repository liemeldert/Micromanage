import {NextResponse} from 'next/server';
import axios from 'axios';
import connectToDatabase from "@/lib/mongodb";
import Tenant from "@/models/tenant";
import {auth} from "@/app/auth";

export const POST = auth(async (req: Request, ctx) => {
    const udid = ctx.params?.udid ?? {};
    const tenant_id = ctx.params?.tenant ?? {};
    const body = await req.json();
    const command = body;

    const db = await connectToDatabase();
    const tenant = await Tenant.findById(tenant_id).exec();

    const API_URL = tenant.mdm_url;
    const API_USERNAME = 'micromdm';
    const API_PASSWORD = tenant.mdm_secret;

    if (!API_URL || !API_USERNAME || !API_PASSWORD) {
        return NextResponse.json({error: 'Missing API configuration'}, {status: 500});
    }

    console.log("command", command);
    console.log("udid", udid);

    try {
        const response = await axios.post(
            `${API_URL}/v1/commands`,
            {...command, udid},
            {
                auth: {
                    username: API_USERNAME,
                    password: API_PASSWORD,
                },
                headers: {
                    'Content-Type': 'application/json',
                },
            }
        );

        return NextResponse.json(response.data);
    } catch (error) {
        console.error('Error sending command:', error);
        return NextResponse.json({error: 'Error sending command'}, {status: 500});
    }
});