import {NextResponse} from 'next/server';
import connectToDatabase from '@/lib/mongodb';
import Device from '@/models/device';
import WebhookEvent from '@/models/WebhookEvent';
import {parse} from '@plist/plist';
import Tenant from "@/models/tenant";

export async function POST(request: Request, {params}: { params: { tenant: string, secret: string } }) {
    await connectToDatabase();
    const data = await request.json();

    const {acknowledge_event} = data;
    const {udid, raw_payload} = acknowledge_event;
    const tenant_id = params.tenant;

    // verify tenant secret
    const tenant = await Tenant.findById(tenant_id).exec();
    if (!tenant || tenant.webhook_secret !== params.secret) {
        return NextResponse.json({success: false, error: 'Invalid tenant secret'}, {status: 401});
    }

    // Decode the base64 encoded plist
    const decodedPayload = Buffer.from(raw_payload, 'base64').toString('utf-8');
    const parsedPayload = parse(decodedPayload) as any;

    // Replace the raw_payload with the parsed JSON in the event data
    const modifiedData = {
        ...data,
        acknowledge_event: {
            ...acknowledge_event,
            raw_payload: parsedPayload,
        },
    };
    modifiedData["tenant_id"] = tenant_id

    // Log the webhook event with the modified data
    await logWebhookEvent(modifiedData);

    // Check if the payload contains device information
    if (parsedPayload.QueryResponses) {
        const deviceInfo = parsedPayload.QueryResponses;
        deviceInfo.UDID = udid;
        deviceInfo.tenant_id = tenant_id

        try {
            // Upsert the device information in the database
            const result = await Device.findOneAndUpdate(
                {UDID: udid},
                {$set: deviceInfo},
                {upsert: true, new: true}
            );
            return NextResponse.json({success: true});
        } catch (error) {
            console.error('Error saving device:', error);
            return NextResponse.json({success: false, error: (error as Error).message}, {status: 500});
        }
    } else {
        return NextResponse.json({success: true, message: 'Event logged but no device information to update.'});
    }
}

async function logWebhookEvent(eventData: any) {
    try {
        await WebhookEvent.create(eventData);
    } catch (error) {
        console.error('Error logging webhook event:', error);
    }
}