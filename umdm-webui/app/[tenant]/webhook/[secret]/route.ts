import {NextResponse} from 'next/server';
import connectToDatabase from '@/lib/mongodb';
import Device from '@/models/device';
import WebhookEvent from '@/models/WebhookEvent';
import {parse} from '@plist/plist';
import Tenant from "@/models/tenant";
import {device_queries, sendCommand} from "@/lib/micromdm";

export async function POST(request: Request, {params}: { params: { tenant: string, secret: string } }) {
    await connectToDatabase();
    const data = await request.json();
    const {checkin_event, acknowledge_event} = data;
    const tenant_id = params.tenant;

    // Verify tenant secret
    const tenant = await Tenant.findById(tenant_id).exec();
    if (!tenant || tenant.webhook_secret !== params.secret) {
        return NextResponse.json({success: false, error: 'Invalid tenant secret'}, {status: 401});
    }

    // Log the webhook event
    await logWebhookEvent({...data, tenant_id});

    if (checkin_event && checkin_event.message_type === "Authenticate") {
        const udid = checkin_event.udid;

        await sendCommand(tenant, udid as string, {
            request_type: "DeviceInformation",
            queries: device_queries,
        });

        return NextResponse.json({success: true, message: 'Device enrollment detected. Requested device information.'});

    } else if (acknowledge_event && acknowledge_event.raw_payload) {
        const udid = acknowledge_event.udid;
        const raw_payload = acknowledge_event.raw_payload;

        // Decode the base64 encoded plist
        const decodedPayload = Buffer.from(raw_payload, 'base64').toString('utf-8');
        const parsedPayload = parse(decodedPayload) as any;

        // Check if the payload contains device information
        if (parsedPayload.QueryResponses) {
            const deviceInfo = parsedPayload.QueryResponses;
            deviceInfo.UDID = udid;
            deviceInfo.tenant_id = tenant_id;

            try {
                // Upsert the device information in the database
                await Device.findOneAndUpdate(
                    {UDID: udid},
                    {$set: deviceInfo},
                    {upsert: true, new: true}
                );

                return NextResponse.json({success: true, message: 'Device information updated.'});
            } catch (error) {
                console.error('Error saving device:', error);
                return NextResponse.json({success: false, error: (error as Error).message}, {status: 500});
            }
        }
    }

    return NextResponse.json({success: true, message: 'Event logged but no device enrollment or information update needed.'});
}

async function logWebhookEvent(eventData: any) {
    try {
        await WebhookEvent.create(eventData);
    } catch (error) {
        console.error('Error logging webhook event:', error);
    }
}