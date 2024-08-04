import {NextResponse} from 'next/server';
import connectToDatabase from '@/lib/mongodb';
import Device from '@/models/device';
import {auth} from '@/app/auth';

export const GET = auth(async (req, ctx) => {
    const session = req.auth;

    if (!session || !session.user || !session.user.id) {
        return NextResponse.json({message: "Not authenticated"}, {status: 401});
    }

    await connectToDatabase();

    try {
        const tenantId = ctx.params?.tenant;

        if (!tenantId || Array.isArray(tenantId)) {
            return NextResponse.json({error: 'Tenant ID is required'}, {status: 400});
        }

        const devices = await Device.find({tenant_id: tenantId});

        return NextResponse.json(devices);
    } catch (error) {
        console.error('Error fetching devices:', error);
        return NextResponse.json({error: 'Error fetching devices'}, {status: 500});
    }
});