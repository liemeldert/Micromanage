"use client"
  import NavigationLayout from "@/app/components/navigation";
import {useParams, useRouter} from "next/navigation";
import {useSession} from "next-auth/react";

import {useTenant} from "@/lib/useTenant";



export default function Layout({
  children
}: Readonly<{
  children: React.ReactNode;
}>) {
  const session = useSession()
  const router = useRouter()
  const tenant = useTenant()

  if (session.status === "unauthenticated") { router.push('/auth/login') }

  return (
    <NavigationLayout>
      {children}
    </NavigationLayout>
  );
}
