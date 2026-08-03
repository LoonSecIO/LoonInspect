import type { PropsWithChildren } from "react";

export function MainContainer({ children }: PropsWithChildren) {
  return <main className="flex-1 p-4">{children}</main>;
}