import {NextResponse} from 'next/server';
import connectToDatabase from '@/lib/mongodb';
import Tenant from "@/models/tenant";
import {auth} from "@/app/auth";

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

        const tenantData = await Tenant.findById(tenantId).exec();

        if (!tenantData) {
            return NextResponse.json({error: 'Tenant not found'}, {status: 404});
        }

        return NextResponse.json(tenantData);
    } catch (error) {
        console.error('Error fetching tenant:', error);
        return NextResponse.json({error: 'Error fetching tenant'}, {status: 500});
    }
});