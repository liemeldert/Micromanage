import {NextResponse} from 'next/server';
import connectToDatabase from '@/lib/mongodb';
import Tenant from "@/models/tenant";
import {auth} from "@/app/auth";

export const GET = auth(async (req) => {
    const session = req.auth;

    if (!session || !session.user || !session.user.id) {
        return NextResponse.json({message: "Not authenticated"}, {status: 401});
    }

    await connectToDatabase();

    try {
        const userId = session.user.id;

        const tenants = await Tenant.find({members: userId});

        return NextResponse.json(tenants, {status: 200});
    } catch (error) {
        console.error('Error fetching tenants:', error);
        return NextResponse.json({error: 'Error fetching tenants'}, {status: 500});
    }
});