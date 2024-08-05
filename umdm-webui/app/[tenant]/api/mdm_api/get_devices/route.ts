import {NextResponse} from 'next/server';
import axios from 'axios';
import {auth} from "@/app/auth";
import Tenant from "@/models/tenant";

export const GET = auth(async (req, ctx) => {
    const tenant_id = ctx.params?.tenant ?? {};

    const tenant = await Tenant.findById(tenant_id).exec();


    const API_URL = tenant.mdm_url;
    const API_USERNAME = 'micromdm';
    const API_PASSWORD = tenant.mdm_secret;

    if (!API_URL || !API_USERNAME || !API_PASSWORD) {
        return NextResponse.json({error: 'Missing API configuration'}, {status: 500});
    }

    try {
        const response = await axios.post(API_URL + "/v1/devices", {
            udid: ""
        }, {
            headers: {
                'Content-Type': 'application/json'
            },
            auth: {
                username: API_USERNAME,
                password: API_PASSWORD,
            },
        });
        console.log("response", response.data);

        return NextResponse.json(response.data);
    } catch (error) {
        console.error('Error fetching devices:', error);
        return NextResponse.json({error: 'Error fetching devices'}, {status: 500});
    }
});
