import {NextResponse} from 'next/server';
import connectToDatabase from '@/lib/mongodb';
import Device from '@/models/device';
import {auth} from "@/app/auth";

export const GET = auth(async (req: Request, ctx) => {
    await connectToDatabase();

    try {
        const device = await Device.findOne({UDID: ctx.params?.udid, tenant_id: ctx.params?.tenant});

        if (!device) {
            console.log(ctx.params)
            return NextResponse.json({error: 'Device not found'}, {status: 404});
        }

        return NextResponse.json(device);
    } catch (error) {
        console.error('Error fetching device:', error);
        return NextResponse.json({error: 'Error fetching device'}, {status: 500});
    }
});

