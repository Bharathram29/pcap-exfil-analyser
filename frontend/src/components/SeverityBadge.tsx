import React from "react";
import { severityClasses } from "../utils/format";

interface SeverityBadgeProps {
  severity: string;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity }) => (
  <span
    className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold tracking-wide ${severityClasses(
      severity,
    )}`}
  >
    {severity.toUpperCase()}
  </span>
);
