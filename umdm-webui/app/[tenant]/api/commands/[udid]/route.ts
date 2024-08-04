import {NextResponse} from 'next/server';
import axios from 'axios';

export async function POST(req: Request, {params}: { params: { udid: string } }) {
    const {udid} = params;
    const body = await req.json();
    const command = body;

    const API_URL = process.env.MICROMDM_URL;
    const API_USERNAME = process.env.MICROMDM_API_USERNAME || 'micromdm';
    const API_PASSWORD = process.env.MICROMDM_API_PASSWORD;

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
}