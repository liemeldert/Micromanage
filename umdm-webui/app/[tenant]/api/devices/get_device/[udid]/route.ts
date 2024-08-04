import {NextResponse} from 'next/server';
import connectToDatabase from '@/lib/mongodb';
import Device from '@/models/device';

export async function GET(req: Request, {params}: { params: { tenant: string, udid: string } }) {
    await connectToDatabase();

    try {
        const device = await Device.findOne({UDID: params.udid, tenant_id: params.tenant});

        if (!device) {
            console.log(params)
            return NextResponse.json({error: 'Device not found'}, {status: 404});
        }

        return NextResponse.json(device);
    } catch (error) {
        console.error('Error fetching device:', error);
        return NextResponse.json({error: 'Error fetching device'}, {status: 500});
    }
}
