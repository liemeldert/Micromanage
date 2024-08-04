import {NextResponse} from 'next/server';
import connectToDatabase from '@/lib/mongodb';
import WebhookEvent from '@/models/WebhookEvent';

export async function GET(req: Request, {params}: { params: { tenant: string, udid: string } }) {
    await connectToDatabase();
    const {udid, tenant} = params;


    try {
        const events = await WebhookEvent.find({'acknowledge_event.udid': udid}).sort({created_at: -1});
        return NextResponse.json(events);
    } catch (error) {
        console.error('Error fetching webhook events:', error);
        return NextResponse.json({error: 'Error fetching webhook events'}, {status: 500});
    }
}
