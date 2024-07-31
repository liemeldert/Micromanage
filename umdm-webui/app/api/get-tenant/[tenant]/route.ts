import { NextResponse } from 'next/server';
import connectToDatabase from '@/lib/mongodb';
import Tenant from "@/models/tenant";

export async function GET(req: Request, { params }: { params: { tenant: string } }) {
    await connectToDatabase();

    try {
        const tenant = await Tenant.findById(params.tenant, '-mdm_secret -webhook_secret').exec();

        if (!tenant) {
            return NextResponse.json({ error: 'Tenant not found' }, { status: 404 });
        }

        return NextResponse.json(tenant);
    } catch (error) {
        console.error('Error fetching device:', error);
        return NextResponse.json({ error: 'Error fetching tenant' }, { status: 500 });
    }
}
