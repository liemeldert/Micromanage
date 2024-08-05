import { NextResponse } from 'next/server';
import connectToDatabase from '@/lib/mongodb';
import Device from '@/models/device';

export async function GET(req: Request, { params }: { params: { tenant: string, profileId: string } }) {
    const { tenant, profileId } = params;

    await connectToDatabase();

    try {
        const devices = await Device.find({ tenantId: tenant, profiles: profileId });
        return NextResponse.json(devices);
    } catch (error) {
        console.error('Error fetching devices with profile:', error);
        return NextResponse.json({ error: 'Error fetching devices with profile' }, { status: 500 });
    }
}