import { NextResponse } from 'next/server';
import axios from 'axios';
import connectToDatabase from "@/lib/mongodb";
import Tenant from "@/models/tenant";
import { auth } from "@/app/auth";

export const POST = auth(async (req: Request, ctx) => {
    const tenant_id = ctx.params?.tenant ?? {};
    const body = await req.json();
    const { command, udids } = body;

    const db = await connectToDatabase();
    const tenant = await Tenant.findById(tenant_id).exec();

    const API_URL = tenant.mdm_url;
    const API_USERNAME = 'micromdm';
    const API_PASSWORD = tenant.mdm_secret;

    if (!API_URL || !API_USERNAME || !API_PASSWORD) {
        return NextResponse.json({error: 'Missing API configuration'}, {status: 500});
    }

    try {
        const responses = await Promise.all(udids.map(async (udid: any) => {
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
            return { udid, response: response.data };
        }));

        return NextResponse.json(responses);
    } catch (error) {
        console.error('Error sending bulk commands:', error);
        return NextResponse.json({error: 'Error sending bulk commands'}, {status: 500});
    }
});