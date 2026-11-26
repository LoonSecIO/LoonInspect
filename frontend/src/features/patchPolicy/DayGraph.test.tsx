// @vitest-environment jsdom
/** The day graph (#614): its accessible name, the day the pointer and the keyboard read out, the table
 *  that carries every value without a hover, and the sentence for a stop that opened nothing. */

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { DayGraph } from "@/features/patchPolicy/DayGraph";
import { walkFixture } from "@/features/patchPolicy/testing/walkFixtures";
import { walkEnglish, walkGerman } from "@/features/patchPolicy/walkCopy";

afterEach(cleanup);

const walk = walkFixture();
const draw = (stop: "7d" | "never" = "7d", words = walkEnglish) =>
  render(<DayGraph policy={walk.policies[stop]} since={walk.window.since} until={walk.window.until} stopName={stop} words={words} num={(value) => String(value)} />);
const readout = () => (document.querySelector("[aria-live]")?.textContent ?? "").trim();
/** The plot's focusable hit area: the one element a reader tabs to. */
const plot = () => document.querySelector<HTMLElement>("[tabindex='0']")!;

describe("DayGraph", () => {
  it("names the series in its accessible name: the ends, the peak, and how many opened and were resolved", () => {
    draw();
    expect(screen.getByRole("img").getAttribute("aria-label")).toBe(
      "Open CVEs per day from 2025-01-01 to 2025-01-10 at 7d: 1 on the first day and 0 on the last, at most 1 (first on 2025-01-01); 1 opened after the first day and 2 were resolved by an update."
    );
  });

  it("draws one opened mark and two resolved marks in the strip, and a legend for all three", () => {
    const { container } = draw();
    expect(container.querySelectorAll("line[class*='eb6834']")).toHaveLength(1);
    expect(container.querySelectorAll("line[class*='1baf7a']")).toHaveLength(2);
    expect(container.textContent).toContain(walkEnglish.legendOpen);
    expect(container.textContent).toContain(walkEnglish.legendNew);
    expect(container.textContent).toContain(walkEnglish.legendResolved);
  });

  it("reads the last day on focus, then moves a day, thirty days, and to either end by key", () => {
    draw();
    fireEvent.focus(plot());
    expect(readout()).toBe("2025-01-10: 0 open, 0 opened, 0 resolved");
    fireEvent.keyDown(plot(), { key: "ArrowLeft" });
    expect(readout()).toBe("2025-01-09: 0 open, 0 opened, 1 resolved, installed 4.4.3");
    fireEvent.keyDown(plot(), { key: "Home" });
    expect(readout()).toMatch(/^2025-01-01: 1 open/);
    fireEvent.keyDown(plot(), { key: "PageDown" });
    expect(readout()).toMatch(/^2025-01-10:/);
    fireEvent.keyDown(plot(), { key: "ArrowRight" });
    expect(readout()).toMatch(/^2025-01-10:/);
    fireEvent.keyDown(plot(), { key: "End" });
    fireEvent.keyDown(plot(), { key: "PageUp" });
    expect(readout()).toBe("2025-01-01: 1 open, 0 opened, 0 resolved");
    fireEvent.blur(plot());
    expect(readout()).toBe("");
  });

  it("snaps the pointer to the day under it", () => {
    draw();
    const target = plot();
    target.getBoundingClientRect = () => ({ left: 0, width: 100, top: 0, height: 10, right: 100, bottom: 10, x: 0, y: 0, toJSON: () => ({}) });
    fireEvent.pointerMove(target, { clientX: 55 });
    expect(readout()).toBe("2025-01-06: 1 open, 1 opened (1 became detectable, 0 entered by an install), 0 resolved");
    expect(target.textContent).toContain("2025-01-06");
    fireEvent.pointerLeave(target);
    expect(readout()).toBe("");
  });

  it("lists every day the count moved, so no value is behind a hover", () => {
    const { container } = draw();
    const rows = [...container.querySelectorAll("tbody tr")].map((row) => [...row.querySelectorAll("td")].map((cell) => cell.textContent));
    expect(rows).toEqual([
      ["2025-01-01", "1", "0", "0", "—"],
      ["2025-01-04", "0", "0", "1", "4.4.2"],
      ["2025-01-06", "1", "1", "0", "—"],
      ["2025-01-09", "0", "0", "1", "4.4.3"]
    ]);
  });

  it("says when no listed CVE was open on any day", () => {
    const quiet = walkFixture().policies["7d"];
    quiet.series.open = quiet.series.open.map(() => 0);
    quiet.series.new = quiet.series.new.map(() => 0);
    quiet.series.resolved = quiet.series.resolved.map(() => 0);
    render(<DayGraph policy={quiet} since="2025-01-01" until="2025-01-10" stopName="7 days" words={walkEnglish} num={String} />);
    expect(document.body.textContent).toContain(walkEnglish.graphEmpty("7 days"));
  });

  it("speaks German", () => {
    draw("never", walkGerman);
    expect(screen.getByRole("img").getAttribute("aria-label")).toMatch(/^Offene CVEs pro Tag von 2025-01-01 bis 2025-01-10 bei never: 1 am ersten Tag und 2 am letzten/);
    expect(plot().getAttribute("aria-label")).toBe(walkGerman.graphKeys);
  });
});
