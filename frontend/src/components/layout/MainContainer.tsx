import type { PropsWithChildren } from "react";

export function MainContainer({ children }: PropsWithChildren) {
  return (
    <main className="flex-1 p-6">
      <div className="mx-auto max-w-7xl">{children}</div>
    </main>
  );
}