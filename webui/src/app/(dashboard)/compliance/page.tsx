"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

// The single "Compliance" page has been split into dedicated visual editors:
// Groups, Apps and Profiles. Keep this route as a redirect for old links.
export default function CompliancePage() {
  const router = useRouter();
  useEffect(() => {
    router.replace("/groups");
  }, [router]);
  return null;
}
