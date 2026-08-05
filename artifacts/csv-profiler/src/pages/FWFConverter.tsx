import { useState, useRef, useCallback, useContext } from "react";
import { useEncryptionSettings } from "@/lib/encryption-settings-context";
import {
  CheckCircle2, AlertTriangle, X, ArrowRight, Download, Eye,
  Layers, RotateCcw, Key, Lock, Shuffle, LockOpen, Search, Columns2,
  Loader2, FileSpreadsheet, Plus, FileText, ChevronDown, ChevronRight,
} from "lucide-react";
import folderIcon from "@assets/open-folder_1781738999125.png";
import {
  parseLayoutFile, readExcelFileInfo, getSheetRowCount, convertFWFToCSV,
  type FieldDef, type ParseLayoutResult, type ExcelFileInfo,
} from "@/lib/fwf-parser";
import {
  encryptFWFToBlob, decryptCSVToBlob, readCSVHeaders,
  type AnonymizeOptions,
} from "@/lib/anonymize";
import { exportAs, EXPORT_FORMATS, type ExportFormat } from "@/lib/format-export";

// ── Types ─────────────────────────────────────────────────────────────────────

interface LayoutEntry {
  id: string;
  file: File;
  fileName: string;
  excelInfo: ExcelFileInfo | null;
  sheetSelectOpen: boolean;
  selectedSheets: string[];   // multi-select — one layout entry created per sheet on confirm
  rowFrom: string;
  rowTo: string;
  sheetRowCount: number;      // row count of single selected sheet (0 when >1 selected)
  applyingSheet: boolean;
  result: ParseLayoutResult | null;
  error: string;
}

interface DataFile {
  id: string;
  fileName: string;
  text: string;
  lineCount: number;
  layoutId: string;
  preview: string[][];
  showPreview: boolean;
  outputBaseName: string;
  error: string;
  activated: boolean;
  step: "ready" | "anon-done";
  encColsList: string[];
  encRunning: boolean;
  encProgress: number;
  encResultKey: string | null;
  encResultBlob: Blob | null;
  encError: string;
  exportingFmts: string[];
  origDownloading: boolean;
  origProgress: number;
}

type AnonMode = "encrypt" | "decrypt";

// ── Helpers ───────────────────────────────────────────────────────────────────

function uid() { return Math.random().toString(36).slice(2, 10); }

function triggerDownload(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

function patchLayout(
  set: React.Dispatch<React.SetStateAction<LayoutEntry[]>>,
  id: string,
  patch: Partial<LayoutEntry>
) {
  set(prev => prev.map(l => l.id === id ? { ...l, ...patch } : l));
}

function patchFile(
  set: React.Dispatch<React.SetStateAction<DataFile[]>>,
  id: string,
  patch: Partial<DataFile>
) {
  set(prev => prev.map(df => df.id === id ? { ...df, ...patch } : df));
}

function blankDataFile(file: File): DataFile {
  return {
    id: uid(), fileName: file.name, text: "", lineCount: 0,
    layoutId: "", preview: [], showPreview: false,
    outputBaseName: file.name.replace(/\.[^.]+$/, ""), error: "",
    activated: false, step: "ready", encColsList: [],
    encRunning: false, encProgress: 0,
    encResultKey: null, encResultBlob: null, encError: "",
    exportingFmts: [], origDownloading: false, origProgress: 0,
  };
}

// ── Main component ────────────────────────────────────────────────────────────

export default function FWFConverter() {
  const [layouts, setLayouts] = useState<LayoutEntry[]>([]);
  const [dataFiles, setDataFiles] = useState<DataFile[]>([]);

  // Global key settings (shared across all file encryptions)
  const [anonMode, setAnonMode] = useState<AnonMode>("encrypt");
  const [anonKeyMode, setAnonKeyMode] = useState<"random" | "pbkdf2" | "hex">("random");
  const [anonSeeds, setAnonSeeds] = useState<number[]>([42, 137, 2024, 7]);
  const [anonPassphrase, setAnonPassphrase] = useState("");
  const [anonPbkdf2Iter, setAnonPbkdf2Iter] = useState(100_000);
  const [anonDeterministic, setAnonDeterministic] = useState(true);
  const { alphanumeric: anonAlphanumeric, setAlphanumeric: setAnonAlphanumeric } = useEncryptionSettings();
  const [anonKeyHexInput, setAnonKeyHexInput] = useState("");

  // Global decrypt panel
  const [decryptFileName, setDecryptFileName] = useState("");
  const [decryptCsvText, setDecryptCsvText] = useState<string | null>(null);
  const [decryptHeaders, setDecryptHeaders] = useState<string[]>([]);
  const [decryptCols, setDecryptCols] = useState<Set<string>>(new Set());
  const [decryptRunning, setDecryptRunning] = useState(false);
  const [decryptProgress, setDecryptProgress] = useState(0);
  const [decryptBlob, setDecryptBlob] = useState<Blob | null>(null);
  const [decryptError, setDecryptError] = useState("");

  // Compare modal
  const [showCompare, setShowCompare] = useState(false);
  const [compareLoading, setCompareLoading] = useState(false);
  const [compareData, setCompareData] = useState<{ headers: string[]; original: string[][]; anonymized: string[][] } | null>(null);
  const [compareTotalRows, setCompareTotalRows] = useState(0);
  const [showDecryptCompare, setShowDecryptCompare] = useState(false);
  const [decryptCompareLoading, setDecryptCompareLoading] = useState(false);
  const [decryptCompareData, setDecryptCompareData] = useState<{ headers: string[]; original: string[][]; anonymized: string[][] } | null>(null);

  const layoutInputRef = useRef<HTMLInputElement>(null);
  const dataInputRef = useRef<HTMLInputElement>(null);
  const decryptInputRef = useRef<HTMLInputElement>(null);

  const buildOpts = (): AnonymizeOptions => ({
    keyMode: anonKeyMode, seeds: anonSeeds,
    passphrase: anonPassphrase, pbkdf2Iterations: anonPbkdf2Iter,
    deterministic: anonDeterministic, keyHex: anonKeyHexInput,
    alphanumericOutput: anonAlphanumeric,
  });

  // ── Layout handlers ──────────────────────────────────────────────────────

  const handleLayoutFiles = useCallback(async (files: File[]) => {
    for (const file of files) {
      const isCSV = /\.(csv|tsv)$/i.test(file.name);
      const entry: LayoutEntry = {
        id: uid(), file, fileName: file.name,
        excelInfo: null, sheetSelectOpen: false,
        selectedSheets: [], rowFrom: "", rowTo: "",
        sheetRowCount: 0, applyingSheet: false, result: null, error: "",
      };
      setLayouts(prev => [...prev, entry]);

      if (isCSV) {
        try {
          const result = await parseLayoutFile(file);
          patchLayout(setLayouts, entry.id, result.fields.length ? { result } : { error: result.warnings.join(" ") || "No fields found." });
        } catch (e) { patchLayout(setLayouts, entry.id, { error: `Parse error: ${(e as Error).message}` }); }
      } else {
        try {
          const info = await readExcelFileInfo(file);
          // Pre-select all sheets so the user can deselect what they don't need
          patchLayout(setLayouts, entry.id, {
            excelInfo: info,
            sheetSelectOpen: true,
            selectedSheets: [...info.sheetNames],
            sheetRowCount: info.sheetNames.length === 1
              ? getSheetRowCount(info.buf, info.sheetNames[0])
              : 0,
          });
        } catch (e) { patchLayout(setLayouts, entry.id, { error: `Read error: ${(e as Error).message}` }); }
      }
    }
  }, []);

  const confirmSheet = useCallback(async (id: string) => {
    const lo = layouts.find(l => l.id === id);
    if (!lo || lo.selectedSheets.length === 0) return;
    patchLayout(setLayouts, id, { applyingSheet: true, error: "" });

    const [firstSheet, ...extraSheets] = lo.selectedSheets;
    const rowOpts = {
      startRow: lo.rowFrom ? parseInt(lo.rowFrom, 10) : undefined,
      endRow:   lo.rowTo   ? parseInt(lo.rowTo,   10) : undefined,
    };

    // Parse the first selected sheet into the current entry
    try {
      const result = await parseLayoutFile(lo.file, { sheetName: firstSheet, ...rowOpts });
      patchLayout(setLayouts, id, result.fields.length
        ? { result, sheetSelectOpen: false, applyingSheet: false }
        : { error: result.warnings.join(" ") || "No fields found.", applyingSheet: false });
    } catch (e) {
      patchLayout(setLayouts, id, { error: `Parse error: ${(e as Error).message}`, applyingSheet: false });
      return; // Don't create extra entries if the first fails
    }

    // Parse each additional selected sheet as a new layout entry
    for (const sheetName of extraSheets) {
      const newEntry: LayoutEntry = {
        id: uid(), file: lo.file, fileName: lo.fileName,
        excelInfo: lo.excelInfo, sheetSelectOpen: false,
        selectedSheets: [sheetName], rowFrom: lo.rowFrom, rowTo: lo.rowTo,
        sheetRowCount: lo.excelInfo ? getSheetRowCount(lo.excelInfo.buf, sheetName) : 0,
        applyingSheet: true, result: null, error: "",
      };
      setLayouts(prev => [...prev, newEntry]);
      try {
        const r = await parseLayoutFile(lo.file, { sheetName, ...rowOpts });
        patchLayout(setLayouts, newEntry.id, r.fields.length
          ? { result: r, applyingSheet: false }
          : { error: r.warnings.join(" ") || "No fields found.", applyingSheet: false });
      } catch (e) {
        patchLayout(setLayouts, newEntry.id, { error: `Parse error: ${(e as Error).message}`, applyingSheet: false });
      }
    }
  }, [layouts]);

  const autoDetectSheet = useCallback(async (id: string) => {
    const lo = layouts.find(l => l.id === id);
    if (!lo) return;
    patchLayout(setLayouts, id, { applyingSheet: true, error: "" });
    try {
      const result = await parseLayoutFile(lo.file);
      patchLayout(setLayouts, id, result.fields.length
        ? { result, sheetSelectOpen: false, applyingSheet: false }
        : { error: result.warnings.join(" ") || "No fields found.", applyingSheet: false });
    } catch (e) { patchLayout(setLayouts, id, { error: `Parse error: ${(e as Error).message}`, applyingSheet: false }); }
  }, [layouts]);

  // "Add Range" — clone same Excel file as a new entry with sheet picker open
  const addRange = useCallback((fromId: string) => {
    const src = layouts.find(l => l.id === fromId);
    if (!src?.excelInfo) return;
    const entry: LayoutEntry = {
      id: uid(), file: src.file, fileName: src.fileName,
      excelInfo: src.excelInfo, sheetSelectOpen: true,
      selectedSheets: [...src.excelInfo.sheetNames], rowFrom: "", rowTo: "",
      sheetRowCount: src.excelInfo.sheetNames.length === 1
        ? getSheetRowCount(src.excelInfo.buf, src.excelInfo.sheetNames[0])
        : 0,
      applyingSheet: false, result: null, error: "",
    };
    setLayouts(prev => [...prev, entry]);
  }, [layouts]);

  const removeLayout = useCallback((id: string) => {
    setLayouts(prev => prev.filter(l => l.id !== id));
    setDataFiles(prev => prev.map(df => df.layoutId === id ? { ...df, layoutId: "", preview: [], activated: false } : df));
  }, []);

  // ── Data file handlers ───────────────────────────────────────────────────

  const handleDataFiles = useCallback(async (files: File[]) => {
    for (const file of files) {
      const df = blankDataFile(file);
      setDataFiles(prev => [...prev, df]);
      try {
        const text = await file.text();
        const lines = text.split(/\r?\n/).filter(l => l.length > 0);
        // If the first line has commas it is a CSV header row — don't count it as a data record
        const hasCsvHeader = lines.length > 0 && lines[0].includes(",");
        patchFile(setDataFiles, df.id, { text, lineCount: hasCsvHeader ? lines.length - 1 : lines.length });
      } catch (e) { patchFile(setDataFiles, df.id, { error: `Read error: ${(e as Error).message}` }); }
    }
  }, []);

  const assignLayout = useCallback((dfId: string, layoutId: string) => {
    setDataFiles(prev => prev.map(df => {
      if (df.id !== dfId) return df;
      const lo = layouts.find(l => l.id === layoutId);
      let preview: string[][] = [];
      if (lo?.result && df.text) {
        let lines = df.text.split(/\r?\n/).filter(l => l.length > 0);
        // Skip CSV header row if present (FWF lines are never comma-delimited)
        if (lines.length > 0 && lines[0].includes(",")) lines = lines.slice(1);
        preview = lines.slice(0, 10).map(line =>
          lo.result!.fields.map(f => line.padEnd(f.end).substring(f.start - 1, f.end).trim())
        );
      }
      const encColsList = lo?.result?.fields.map(f => f.varName) ?? [];
      return { ...df, layoutId, preview, activated: false, step: "ready", encColsList, encResultBlob: null, encResultKey: null, encError: "" };
    }));
  }, [layouts]);

  const removeDataFile = useCallback((id: string) => {
    setDataFiles(prev => prev.filter(df => df.id !== id));
  }, []);

  const activateDataFile = useCallback((id: string) => {
    setDataFiles(prev => prev.map(df => {
      if (df.id !== id) return df;
      const lo = layouts.find(l => l.id === df.layoutId);
      const encColsList = lo?.result?.fields.map(f => f.varName) ?? [];
      return { ...df, activated: true, encColsList };
    }));
  }, [layouts]);

  // ── Per-file processing ──────────────────────────────────────────────────

  const handleEncrypt = useCallback(async (dfId: string) => {
    setDataFiles(prev => {
      const df = prev.find(d => d.id === dfId);
      const lo = df ? layouts.find(l => l.id === df.layoutId) : null;
      if (!df || !lo?.result || !df.text || df.encColsList.length === 0) {
        return prev.map(d => d.id === dfId
          ? { ...d, encError: d.encColsList.length === 0 ? "Select at least one column to encrypt." : d.encError }
          : d);
      }
      return prev.map(d => d.id === dfId ? { ...d, encRunning: true, encProgress: 0, encError: "", encResultBlob: null, encResultKey: null } : d);
    });

    // Use a small timeout so the state update above renders before the heavy work starts
    await new Promise(r => setTimeout(r, 20));

    const df = dataFiles.find(d => d.id === dfId);
    const lo = df ? layouts.find(l => l.id === df.layoutId) : null;
    if (!df || !lo?.result || !df.text) return;
    if (df.encColsList.length === 0) return;

    try {
      const { blob, keyHex } = await encryptFWFToBlob(
        df.text, lo.result.fields, new Set(df.encColsList), buildOpts(),
        pct => patchFile(setDataFiles, dfId, { encProgress: pct })
      );
      patchFile(setDataFiles, dfId, { encResultBlob: blob, encResultKey: keyHex, step: "anon-done", encRunning: false });
    } catch (e) {
      patchFile(setDataFiles, dfId, { encError: `Encryption failed: ${(e as Error).message}`, encRunning: false });
    }
  }, [dataFiles, layouts, anonKeyMode, anonSeeds, anonPassphrase, anonPbkdf2Iter, anonDeterministic, anonAlphanumeric, anonKeyHexInput]);

  const handleDownloadOriginal = useCallback(async (dfId: string) => {
    const df = dataFiles.find(d => d.id === dfId);
    const lo = df ? layouts.find(l => l.id === df.layoutId) : null;
    if (!df || !lo?.result || !df.text) return;
    patchFile(setDataFiles, dfId, { origDownloading: true, origProgress: 0 });
    try {
      const blob = await convertFWFToCSV(df.text, lo.result.fields, {
        onProgress: pct => patchFile(setDataFiles, dfId, { origProgress: pct }),
      });
      triggerDownload(blob, `${df.outputBaseName}.csv`);
    } finally { patchFile(setDataFiles, dfId, { origDownloading: false, origProgress: 0 }); }
  }, [dataFiles, layouts]);

  const handleExport = async (dfId: string, fmt: ExportFormat, blob: Blob, fields: FieldDef[], baseName: string) => {
    patchFile(setDataFiles, dfId, { exportingFmts: [...(dataFiles.find(d => d.id === dfId)?.exportingFmts ?? []), fmt] });
    await exportAs(fmt, blob, fields, baseName);
    setDataFiles(prev => prev.map(df => df.id === dfId ? { ...df, exportingFmts: df.exportingFmts.filter(f => f !== fmt) } : df));
  };

  const handleOpenCompare = async (dfId: string) => {
    const df = dataFiles.find(d => d.id === dfId);
    const lo = df ? layouts.find(l => l.id === df.layoutId) : null;
    if (!df?.encResultBlob || !lo?.result) return;
    setCompareLoading(true); setShowCompare(true); setCompareTotalRows(df.lineCount);
    try {
      const MAX = 500;
      const headers = lo.result.fields.map(f => f.varName);
      let fwfLines = df.text.split(/\r?\n/).filter(l => l.length > 0);
      // Skip CSV header row if present (FWF lines are never comma-delimited)
      if (fwfLines.length > 0 && fwfLines[0].includes(",")) fwfLines = fwfLines.slice(1);
      const original = fwfLines.slice(0, MAX).map(line =>
        lo.result!.fields.map(f => line.padEnd(f.end).substring(f.start - 1, f.end).trim())
      );
      const anonText = await df.encResultBlob.text();
      const anonLines = anonText.split(/\r?\n/).filter(l => l.length > 0);
      const parseCSVLine = (line: string): string[] => {
        const cells: string[] = []; let cur = ""; let inQ = false;
        for (const ch of line) { if (ch === '"') { inQ = !inQ; } else if (ch === "," && !inQ) { cells.push(cur); cur = ""; } else { cur += ch; } }
        cells.push(cur); return cells;
      };
      const anonymized = anonLines.slice(1, MAX + 1).map(parseCSVLine);
      setCompareData({ headers, original, anonymized });
    } finally { setCompareLoading(false); }
  };

  // ── Decrypt handlers ─────────────────────────────────────────────────────

  const handleDecryptFile = useCallback(async (file: File) => {
    setDecryptError(""); setDecryptBlob(null); setDecryptFileName(file.name);
    setDecryptCsvText(null); setDecryptHeaders([]);
    const text = await file.text();
    const headers = readCSVHeaders(text);
    if (!headers.length) { setDecryptError("Could not read CSV headers."); return; }
    setDecryptCsvText(text); setDecryptHeaders(headers); setDecryptCols(new Set(headers));
  }, []);

  const handleDecrypt = useCallback(async () => {
    if (!decryptCsvText) { setDecryptError("Upload an encrypted CSV first."); return; }
    if (decryptCols.size === 0) { setDecryptError("Select at least one column to decrypt."); return; }
    setDecryptRunning(true); setDecryptProgress(0); setDecryptError(""); setDecryptBlob(null);
    try {
      const blob = await decryptCSVToBlob(decryptCsvText, decryptCols, buildOpts(), setDecryptProgress);
      setDecryptBlob(blob);
    } catch (e) { setDecryptError(`Decryption failed: ${(e as Error).message}`); }
    finally { setDecryptRunning(false); }
  }, [decryptCsvText, decryptCols, anonKeyMode, anonSeeds, anonPassphrase, anonPbkdf2Iter, anonDeterministic, anonKeyHexInput]);

  const handleOpenDecryptCompare = useCallback(async () => {
    if (!decryptCsvText || !decryptBlob) return;
    setDecryptCompareLoading(true); setShowDecryptCompare(true);
    try {
      const MAX = 500;
      const parseCSVLine = (line: string): string[] => {
        const cells: string[] = []; let cur = ""; let inQ = false;
        for (const ch of line) { if (ch === '"') { inQ = !inQ; } else if (ch === "," && !inQ) { cells.push(cur); cur = ""; } else { cur += ch; } }
        cells.push(cur); return cells;
      };
      // Skip v2 format comment lines (start with "#") so the first data line
      // is treated as the CSV header, not the "# AIRAVATA-FORMAT: v2" comment.
      const encLines = decryptCsvText.split(/\r?\n/).filter(l => l.trim().length > 0 && !l.startsWith("#"));
      const headers = parseCSVLine(encLines[0]);
      const original = encLines.slice(1, MAX + 1).map(parseCSVLine);
      const decText = await decryptBlob.text();
      const decLines = decText.split(/\r?\n/).filter(l => l.trim().length > 0);
      const anonymized = decLines.slice(1, MAX + 1).map(parseCSVLine);
      setDecryptCompareData({ headers, original, anonymized });
    } finally { setDecryptCompareLoading(false); }
  }, [decryptCsvText, decryptBlob]);

  // ── Computed ─────────────────────────────────────────────────────────────

  const readyLayouts = layouts.filter(l => l.result !== null);
  const assignedFiles = dataFiles.filter(df => df.layoutId !== "");
  const activatedFiles = dataFiles.filter(df => df.activated);
  const keyModeLabel = anonKeyMode === "random" ? `seeds = [${anonSeeds.join(", ")}]` : anonKeyMode === "pbkdf2" ? `PBKDF2 (${anonPbkdf2Iter.toLocaleString()} iter)` : "raw hex key";

  const phase = readyLayouts.length === 0 ? 0 : assignedFiles.length === 0 ? 1 : 2;

  return (
    <div className="space-y-8">

      {/* Always-mounted hidden input for decrypt so the ref is never nulled out */}
      <input ref={decryptInputRef} type="file" accept=".csv" className="hidden"
        onChange={e => { const f = Array.from(e.target.files ?? []); if (f.length) handleDecryptFile(f[0]); e.target.value = ""; }} />

      {/* ── Step indicator ────────────────────────────────────────────────── */}
      <div className="flex items-center justify-center gap-3 flex-wrap">
        {(["Upload layouts", "Assign to data files", "Process & download"] as const).map((label, idx) => (
          <span key={idx} className="flex items-center gap-3">
            {idx > 0 && <ArrowRight className="w-4 h-4 text-gray-300 flex-shrink-0" />}
            <StepBadge n={idx + 1} label={label} active={idx === phase} done={idx < phase} />
          </span>
        ))}
      </div>

      {/* ── Two-panel: layout manager + data file manager ─────────────────── */}
      <div className="grid grid-cols-1 gap-8 lg:grid-cols-2 min-w-0">

        {/* LEFT: Layout Manager */}
        <div className="border border-gray-200 rounded-2xl p-6 space-y-4 min-w-0 overflow-hidden">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-black">Step 1 — Layout files</h2>
              <p className="text-sm text-gray-500 mt-0.5">Excel (.xlsx) or CSV with Field_Name, Start, End columns</p>
            </div>
            <button
              onClick={() => layoutInputRef.current?.click()}
              className="flex items-center gap-1.5 text-sm font-semibold px-3 py-2 rounded-xl bg-black text-white hover:bg-gray-800 transition-colors flex-shrink-0">
              <Plus className="w-4 h-4" />Add layout
            </button>
            <input ref={layoutInputRef} type="file" accept=".xlsx,.xls,.csv" multiple className="hidden"
              onChange={e => { const f = Array.from(e.target.files ?? []); if (f.length) handleLayoutFiles(f); e.target.value = ""; }} />
          </div>

          {layouts.length === 0 ? (
            <DropZone accept=".xlsx,.xls,.csv" multiple icon={<img src={folderIcon} className="w-20 h-20 object-contain" alt="" />}
              label="Drop layout files here" sublabel="Excel or CSV — multiple files supported"
              inputRef={layoutInputRef} onFiles={handleLayoutFiles} />
          ) : (
            <div className="space-y-3">
              {layouts.map(lo => (
                <LayoutCard key={lo.id} lo={lo}
                  onConfirmSheet={() => confirmSheet(lo.id)}
                  onAutoDetect={() => autoDetectSheet(lo.id)}
                  onSheetToggle={sheet => {
                    const cur = lo.selectedSheets;
                    const next = cur.includes(sheet) ? cur.filter(s => s !== sheet) : [...cur, sheet];
                    patchLayout(setLayouts, lo.id, {
                      selectedSheets: next,
                      sheetRowCount: next.length === 1 && lo.excelInfo
                        ? getSheetRowCount(lo.excelInfo.buf, next[0]) : 0,
                    });
                  }}
                  onSelectAllSheets={() => patchLayout(setLayouts, lo.id, {
                    selectedSheets: lo.excelInfo ? [...lo.excelInfo.sheetNames] : [],
                    sheetRowCount: lo.excelInfo?.sheetNames.length === 1
                      ? getSheetRowCount(lo.excelInfo.buf, lo.excelInfo.sheetNames[0]) : 0,
                  })}
                  onDeselectAllSheets={() => patchLayout(setLayouts, lo.id, {
                    selectedSheets: [],
                    sheetRowCount: 0,
                  })}
                  onRangeChange={(from, to) => patchLayout(setLayouts, lo.id, { rowFrom: from, rowTo: to })}
                  onAddRange={() => addRange(lo.id)}
                  onRemove={() => removeLayout(lo.id)}
                />
              ))}
              <button onClick={() => layoutInputRef.current?.click()}
                className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl border-2 border-dashed border-gray-200 text-sm text-gray-400 hover:border-blue-400 hover:text-blue-600 transition-colors">
                <Plus className="w-4 h-4" />Add more layout files
              </button>
            </div>
          )}
        </div>

        {/* RIGHT: Data File Manager */}
        <div className="border border-gray-200 rounded-2xl p-6 space-y-4 min-w-0 overflow-hidden">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-black">Step 2 — Data files (.TXT)</h2>
              <p className="text-sm text-gray-500 mt-0.5">Fixed-width records — assign a layout to each</p>
            </div>
            <button
              onClick={() => dataInputRef.current?.click()}
              disabled={readyLayouts.length === 0}
              className="flex items-center gap-1.5 text-sm font-semibold px-3 py-2 rounded-xl bg-black text-white hover:bg-gray-800 disabled:opacity-40 transition-colors flex-shrink-0">
              <Plus className="w-4 h-4" />Add files
            </button>
            <input ref={dataInputRef} type="file" accept=".txt,.dat,.fwf,.data" multiple className="hidden"
              onChange={e => { const f = Array.from(e.target.files ?? []); if (f.length) handleDataFiles(f); e.target.value = ""; }} />
          </div>

          {readyLayouts.length === 0 ? (
            <div className="flex items-center justify-center h-44 text-sm text-gray-400 border-2 border-dashed border-gray-200 rounded-2xl text-center px-6">
              Load at least one layout first
            </div>
          ) : dataFiles.length === 0 ? (
            <DropZone accept=".txt,.dat,.fwf,.data" multiple icon={<img src={folderIcon} className="w-20 h-20 object-contain" alt="" />}
              label="Drop data files here" sublabel=".TXT, .DAT or any fixed-width file"
              inputRef={dataInputRef} onFiles={handleDataFiles} />
          ) : (
            <div className="space-y-3">
              {dataFiles.map(df => (
                <DataFileRow key={df.id} df={df} readyLayouts={readyLayouts}
                  onAssign={lid => assignLayout(df.id, lid)}
                  onTogglePreview={() => patchFile(setDataFiles, df.id, { showPreview: !df.showPreview })}
                  onProcess={() => activateDataFile(df.id)}
                  onRemove={() => removeDataFile(df.id)}
                />
              ))}
              <button onClick={() => dataInputRef.current?.click()}
                className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl border-2 border-dashed border-gray-200 text-sm text-gray-400 hover:border-blue-400 hover:text-blue-600 transition-colors">
                <Plus className="w-4 h-4" />Add more data files
              </button>
            </div>
          )}
        </div>
      </div>

      {/* ── Global encryption settings (shown when any file is activated) ── */}
      {activatedFiles.length > 0 && (
        <div className="border border-gray-200 rounded-2xl overflow-hidden">
          <div className="bg-emerald-50 border-b border-emerald-100 px-6 py-5 flex flex-col sm:flex-row sm:items-center gap-4">
            <div className="flex items-center gap-4 flex-1 min-w-0">
              <div className="w-12 h-12 rounded-2xl bg-white border border-emerald-200 flex items-center justify-center flex-shrink-0">
                <Lock className="w-6 h-6 text-emerald-600" />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-black">Step 3 — 4-Round FPE Anonymize / Decrypt</h2>
                <p className="text-sm text-gray-500 mt-0.5">Key settings apply to all files below</p>
              </div>
            </div>
            <div className="flex items-center rounded-xl border border-emerald-200 overflow-hidden text-sm font-semibold flex-shrink-0 bg-white">
              {(["encrypt", "decrypt"] as const).map(m => (
                <button key={m} onClick={() => setAnonMode(m)}
                  className={`flex items-center gap-2 px-5 py-2.5 transition-colors ${m !== "encrypt" ? "border-l border-gray-200" : ""} ${anonMode === m ? "bg-emerald-500 text-white" : "hover:bg-gray-50 text-gray-500"}`}>
                  {m === "encrypt" ? <Lock className="w-4 h-4" /> : <LockOpen className="w-4 h-4" />}
                  {m === "encrypt" ? "Encrypt" : "Decrypt"}
                </button>
              ))}
            </div>
          </div>
          <div className="p-6">
            <KeySettings
              keyMode={anonKeyMode} setKeyMode={setAnonKeyMode}
              seeds={anonSeeds} setSeeds={setAnonSeeds}
              passphrase={anonPassphrase} setPassphrase={setAnonPassphrase}
              pbkdf2Iter={anonPbkdf2Iter} setPbkdf2Iter={setAnonPbkdf2Iter}
              deterministic={anonDeterministic} setDeterministic={setAnonDeterministic}
              alphanumeric={anonAlphanumeric} setAlphanumeric={setAnonAlphanumeric}
              keyHexInput={anonKeyHexInput} setKeyHexInput={setAnonKeyHexInput}
            />
          </div>
        </div>
      )}

      {/* ── Per-file processing cards ─────────────────────────────────────── */}
      {activatedFiles.map(df => {
        const lo = layouts.find(l => l.id === df.layoutId);
        if (!lo?.result) return null;
        const fields = lo.result.fields;
        const allColNames = fields.map(f => f.varName);
        const encCols = new Set(df.encColsList);

        return (
          <div key={df.id} className="border border-gray-200 rounded-2xl overflow-hidden">
            {/* Card header */}
            <div className="px-6 py-4 bg-gray-50 border-b border-gray-200 flex items-center gap-3">
              <FileText className="w-4 h-4 text-gray-400 flex-shrink-0" />
              <div className="flex-1 min-w-0">
                <p className="font-semibold text-black text-sm truncate">{df.fileName}</p>
                <p className="text-xs text-gray-500 mt-0.5">{df.lineCount.toLocaleString()} records · {fields.length} columns · layout: {lo.result.sheetName || lo.fileName}</p>
              </div>
              {df.step === "anon-done" && <span className="flex items-center gap-1.5 text-xs font-semibold text-emerald-700 bg-emerald-50 border border-emerald-200 px-2.5 py-1 rounded-lg flex-shrink-0"><CheckCircle2 className="w-3.5 h-3.5" />Done</span>}
              <button onClick={() => patchFile(setDataFiles, df.id, { activated: false })}
                className="text-gray-400 hover:text-black flex-shrink-0"><X className="w-4 h-4" /></button>
            </div>

            <div className="p-6 space-y-5">

              {anonMode === "encrypt" && (
                <>
                  <ColSelector allCols={allColNames} selected={encCols}
                    onChange={s => patchFile(setDataFiles, df.id, { encColsList: [...s] })}
                    label="Columns to encrypt" />

                  {df.encError && <ErrorBox message={df.encError} />}
                  {df.encRunning && <ProgressBar pct={df.encProgress} label={`Encrypting ${df.encColsList.length} column${df.encColsList.length !== 1 ? "s" : ""} across ${df.lineCount.toLocaleString()} records…`} icon={<Shuffle className="w-4 h-4 animate-spin" />} />}
                  {df.origDownloading && <ProgressBar pct={df.origProgress} label="Building original CSV…" icon={<Download className="w-4 h-4 animate-pulse" />} />}

                  {df.step !== "anon-done" ? (
                    <div className="flex flex-col sm:flex-row gap-3">
                      <button onClick={() => handleEncrypt(df.id)} disabled={df.encRunning || df.origDownloading || df.encColsList.length === 0}
                        className="flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-xl bg-black text-white text-base font-semibold hover:bg-gray-800 disabled:opacity-50 transition-colors">
                        {df.encRunning ? <><Spin />Anonymizing…</> : <><Lock className="w-4 h-4" />Apply 4-round FPE anonymization</>}
                      </button>
                      <button onClick={() => handleDownloadOriginal(df.id)} disabled={df.encRunning || df.origDownloading}
                        className="flex items-center justify-center gap-2 px-4 py-3 rounded-xl border border-gray-200 text-sm text-gray-500 hover:text-black hover:border-gray-400 disabled:opacity-50 transition-colors whitespace-nowrap">
                        <Download className="w-4 h-4" />Download original CSV
                      </button>
                    </div>
                  ) : (
                    df.encResultBlob && df.encResultKey && (
                      <div className="space-y-5">
                        <SuccessBadge text={`Encryption complete — ${df.encColsList.length} column${df.encColsList.length !== 1 ? "s" : ""} encrypted`} />

                        <div className="border-l-4 border-amber-400 bg-amber-50 rounded-r-xl p-5 space-y-3">
                          <p className="text-sm font-semibold text-amber-800 flex items-center gap-2"><Key className="w-4 h-4" />Symmetric Key — save to decrypt later</p>
                          <div className="font-mono text-xs bg-white rounded-lg px-4 py-3 break-all select-all cursor-text leading-relaxed text-black border border-amber-200">{df.encResultKey}</div>
                          <div className="flex flex-wrap gap-2 items-center">
                            <span className="text-sm text-amber-700 flex-1 min-w-0">4-round FPE · {keyModeLabel} · det. {anonDeterministic ? "ON" : "OFF"}</span>
                            <button onClick={() => navigator.clipboard.writeText(df.encResultKey!)}
                              className="text-sm px-3 py-1.5 rounded-lg border border-amber-300 text-amber-800 hover:bg-amber-100 transition-colors font-medium">Copy key</button>
                            <button onClick={() => {
                              const txt = ["AIRAVATA DEA FPE Key Material", "=".repeat(40), "", `Key (256-bit hex): ${df.encResultKey}`, "", `Key derivation: ${keyModeLabel}`, `Deterministic mode: ${anonDeterministic ? "ON" : "OFF"}`, `File: ${df.fileName}`, `Generated: ${new Date().toISOString()}`, "", "IMPORTANT — Store this key material securely. It is required to decrypt."].join("\n");
                              triggerDownload(new Blob([txt], { type: "text/plain" }), `key_${df.outputBaseName}.txt`);
                            }} className="flex items-center gap-1.5 text-sm px-3 py-1.5 rounded-lg border border-amber-300 text-amber-800 hover:bg-amber-100 transition-colors font-medium">
                              <Download className="w-3.5 h-3.5" />Download key
                            </button>
                          </div>
                          <p className="text-sm text-amber-700">⚠ Same key decrypts. Store securely — never log or share.</p>
                        </div>

                        {/* Format download panel */}
                        <div className="border border-gray-200 rounded-xl overflow-hidden">
                          {EXPORT_FORMATS.map((fmt, idx) => {
                            const isRunning = df.exportingFmts.includes(fmt.id);
                            return (
                              <div key={fmt.id} className={`flex items-center gap-3 px-4 py-3 bg-white ${idx !== EXPORT_FORMATS.length - 1 ? "border-b border-gray-100" : ""}`}>
                                <span className="text-xs font-bold px-1.5 py-0.5 rounded bg-gray-100 text-gray-600 font-mono flex-shrink-0">{fmt.ext}</span>
                                <span className="flex-1 min-w-0">
                                  <span className="text-sm font-semibold text-black block">{fmt.label}</span>
                                  <span className="text-xs text-gray-400 truncate block">{fmt.description}</span>
                                </span>
                                <button disabled={isRunning}
                                  onClick={() => handleExport(df.id, fmt.id, df.encResultBlob!, fields, df.outputBaseName)}
                                  className="flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-lg border border-emerald-300 text-emerald-700 hover:bg-emerald-100 disabled:opacity-40 disabled:cursor-not-allowed transition-colors flex-shrink-0 whitespace-nowrap">
                                  {isRunning ? <><Loader2 className="w-3.5 h-3.5 animate-spin" />Saving…</> : <><Download className="w-3.5 h-3.5" />Download</>}
                                </button>
                              </div>
                            );
                          })}
                        </div>

                        <div className="flex flex-col sm:flex-row gap-3">
                          <button onClick={() => handleOpenCompare(df.id)}
                            className="flex items-center justify-center gap-2 px-4 py-3 rounded-xl border-2 border-emerald-500 text-emerald-700 text-sm font-semibold hover:bg-emerald-50 transition-colors">
                            <Columns2 className="w-4 h-4" />View side by side
                          </button>
                          <button onClick={() => handleDownloadOriginal(df.id)} disabled={df.origDownloading}
                            className="flex items-center justify-center gap-2 px-4 py-3 rounded-xl border border-gray-200 text-sm text-gray-500 hover:text-black hover:border-gray-400 disabled:opacity-50 transition-colors">
                            <Download className="w-4 h-4" />Download original CSV
                          </button>
                        </div>
                        {df.origDownloading && <ProgressBar pct={df.origProgress} label="Building original CSV…" icon={<Download className="w-4 h-4 animate-pulse" />} />}

                        <button onClick={() => patchFile(setDataFiles, df.id, { step: "ready", encResultBlob: null, encResultKey: null, encProgress: 0 })}
                          className="w-full text-sm text-gray-400 hover:text-black text-center transition-colors">
                          ← Change column selection or key settings
                        </button>
                      </div>
                    )
                  )}
                </>
              )}

              {anonMode === "decrypt" && (
                <div className="space-y-5">
                  <p className="text-sm text-gray-500">Decrypt mode: upload an encrypted CSV created from this or another file.</p>
                  {!decryptCsvText ? (
                    <DropZone accept=".csv" icon={<LockOpen className="w-9 h-9 text-blue-600" />}
                      label="Drop anonymized CSV here" sublabel=".CSV encrypted by this tool"
                      inputRef={decryptInputRef} onFiles={files => handleDecryptFile(files[0])} />
                  ) : (
                    <div className="space-y-4">
                      <div className="flex items-center gap-2">
                        <SuccessBadge text={`${decryptFileName} — ${decryptHeaders.length} columns`} />
                        <button onClick={() => { setDecryptFileName(""); setDecryptCsvText(null); setDecryptHeaders([]); setDecryptCols(new Set()); setDecryptBlob(null); }}
                          className="ml-auto text-gray-400 hover:text-black"><X className="w-4 h-4" /></button>
                      </div>
                      <ColSelector allCols={decryptHeaders} selected={decryptCols} onChange={setDecryptCols} label="Columns to decrypt" />
                    </div>
                  )}
                  {decryptError && <ErrorBox message={decryptError} />}
                  {decryptRunning && <ProgressBar pct={decryptProgress} label={`Decrypting ${decryptCols.size} column${decryptCols.size !== 1 ? "s" : ""}…`} icon={<Shuffle className="w-4 h-4 animate-spin" />} />}
                  {!decryptBlob ? (
                    <button onClick={handleDecrypt} disabled={decryptRunning || !decryptCsvText || decryptCols.size === 0}
                      className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-xl bg-black text-white text-base font-semibold hover:bg-gray-800 disabled:opacity-50 transition-colors">
                      {decryptRunning ? <><Spin />Decrypting…</> : <><LockOpen className="w-4 h-4" />Apply 4-round FPE decryption</>}
                    </button>
                  ) : (
                    <div className="space-y-4">
                      <SuccessBadge text="Decryption complete — original values restored" />
                      <div className="flex flex-col sm:flex-row gap-3">
                        <button onClick={() => triggerDownload(decryptBlob!, `${decryptFileName.replace(/\.csv$/i, "")}_decrypted.csv`)}
                          className="flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-xl bg-emerald-600 text-white font-semibold hover:bg-emerald-700 transition-colors">
                          <Download className="w-4 h-4" />Download decrypted CSV
                        </button>
                        <button onClick={handleOpenDecryptCompare}
                          className="flex items-center justify-center gap-2 px-4 py-3 rounded-xl border-2 border-emerald-500 text-emerald-700 text-sm font-semibold hover:bg-emerald-50 transition-colors">
                          <Columns2 className="w-4 h-4" />View side by side
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        );
      })}

      {/* ── Compare modals ────────────────────────────────────────────────── */}
      {showCompare && (
        <SideBySideModal loading={compareLoading} data={compareData} totalRows={compareTotalRows}
          onClose={() => { setShowCompare(false); setCompareData(null); }} />
      )}
      {showDecryptCompare && (
        <SideBySideModal loading={decryptCompareLoading} data={decryptCompareData}
          totalRows={decryptCompareData?.original.length ?? 0}
          leftLabel="Encrypted" rightLabel="Decrypted"
          onClose={() => { setShowDecryptCompare(false); setDecryptCompareData(null); }} />
      )}
    </div>
  );
}

// ── LayoutCard ────────────────────────────────────────────────────────────────

function LayoutCard({ lo, onConfirmSheet, onAutoDetect, onSheetToggle, onSelectAllSheets, onDeselectAllSheets, onRangeChange, onAddRange, onRemove }: {
  lo: LayoutEntry;
  onConfirmSheet: () => void;
  onAutoDetect: () => void;
  onSheetToggle: (sheet: string) => void;
  onSelectAllSheets: () => void;
  onDeselectAllSheets: () => void;
  onRangeChange: (from: string, to: string) => void;
  onAddRange: () => void;
  onRemove: () => void;
}) {
  const done = lo.result !== null;
  const fields = lo.result?.fields ?? [];

  return (
    <div className={`border rounded-xl overflow-hidden ${done ? "border-emerald-200" : lo.error ? "border-red-200" : "border-gray-200"}`}>
      {/* Header row */}
      <div className={`flex items-center gap-3 px-4 py-3 ${done ? "bg-emerald-50" : lo.error ? "bg-red-50" : "bg-gray-50"}`}>
        {done
          ? <CheckCircle2 className="w-4 h-4 text-emerald-600 flex-shrink-0" />
          : lo.error
          ? <AlertTriangle className="w-4 h-4 text-red-500 flex-shrink-0" />
          : <Spin />}
        <div className="flex-1 min-w-0">
          <p className="text-sm font-semibold text-black truncate">{lo.fileName}</p>
          {done && <p className="text-xs text-emerald-700">{fields.length} fields{lo.result?.sheetName ? ` · ${lo.result.sheetName}` : ""}</p>}
          {lo.error && <p className="text-xs text-red-600 truncate">{lo.error}</p>}
          {!done && !lo.error && !lo.sheetSelectOpen && <p className="text-xs text-gray-500">Parsing…</p>}
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          {done && lo.excelInfo && (
            <button onClick={onAddRange}
              className="flex items-center gap-1 text-xs px-2.5 py-1 rounded-lg border border-blue-200 text-blue-700 hover:bg-blue-50 transition-colors font-medium whitespace-nowrap">
              <Plus className="w-3 h-3" />Add range
            </button>
          )}
          <button onClick={onRemove} className="text-gray-400 hover:text-black"><X className="w-4 h-4" /></button>
        </div>
      </div>

      {/* Field preview (when done) */}
      {done && fields.length > 0 && (
        <div className="overflow-auto max-h-44 border-t border-gray-100">
          <table className="w-full text-xs border-collapse">
            <thead className="bg-gray-50 sticky top-0">
              <tr>{["#", "Variable", "Full Name", "Start", "End", "Len"].map(h => (
                <th key={h} className="px-2.5 py-1.5 text-left border-r last:border-r-0 border-gray-200 text-gray-500 font-semibold whitespace-nowrap">{h}</th>
              ))}</tr>
            </thead>
            <tbody>
              {fields.map(f => (
                <tr key={f.srlNo} className="border-t border-gray-100 hover:bg-gray-50">
                  <td className="px-2.5 py-1.5 text-gray-400 font-mono border-r border-gray-100">{f.srlNo}</td>
                  <td className="px-2.5 py-1.5 font-semibold text-black border-r border-gray-100 whitespace-nowrap">{f.varName}</td>
                  <td className="px-2.5 py-1.5 text-gray-600 border-r border-gray-100 max-w-[140px] truncate">{f.fullName}</td>
                  <td className="px-2.5 py-1.5 text-center font-mono text-black border-r border-gray-100">{f.start}</td>
                  <td className="px-2.5 py-1.5 text-center font-mono text-black border-r border-gray-100">{f.end}</td>
                  <td className="px-2.5 py-1.5 text-center font-mono text-black">{f.length}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Sheet selector (inline) — multi-select */}
      {lo.sheetSelectOpen && lo.excelInfo && (() => {
        const allSheets = lo.excelInfo.sheetNames;
        const sel = lo.selectedSheets;
        const allSelected = sel.length === allSheets.length;
        const noneSelected = sel.length === 0;
        return (
          <div className="p-4 space-y-4 border-t border-gray-100 bg-white">
            {/* Header: badge + select-all toggle */}
            <div className="flex items-center justify-between gap-2">
              <InfoBadge
                icon={<FileSpreadsheet className="w-4 h-4" />}
                text={`${allSheets.length} sheet${allSheets.length !== 1 ? "s" : ""} found — ${sel.length} selected`}
              />
              <button
                onClick={() => allSelected ? onDeselectAllSheets() : onSelectAllSheets()}
                className="text-xs text-blue-600 hover:text-blue-800 font-medium whitespace-nowrap"
              >
                {allSelected ? "Deselect all" : "Select all"}
              </button>
            </div>

            {/* Checkbox list */}
            <div className="space-y-1.5 max-h-36 overflow-y-auto pr-1">
              {allSheets.map(name => {
                const checked = sel.includes(name);
                return (
                  <label key={name} className={`flex items-center gap-3 px-3 py-2 rounded-xl border cursor-pointer text-sm transition-colors ${checked ? "border-blue-500 bg-blue-50 text-black" : "border-gray-200 hover:border-blue-300 text-gray-500"}`}>
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => onSheetToggle(name)}
                      className="accent-blue-600 w-4 h-4 flex-shrink-0 rounded"
                    />
                    <span className="font-medium truncate">{name}</span>
                    {checked && sel.length === 1 && lo.sheetRowCount > 0 && (
                      <span className="ml-auto text-xs text-gray-400 flex-shrink-0">{lo.sheetRowCount} rows</span>
                    )}
                  </label>
                );
              })}
            </div>

            {/* Row range — shown for all selections; note added for multi */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <p className="text-sm font-semibold text-black">
                  Row range
                  {sel.length === 1 && lo.sheetRowCount > 0 && (
                    <span className="font-normal text-gray-500 ml-1">({lo.sheetRowCount} rows)</span>
                  )}
                  {sel.length > 1 && (
                    <span className="font-normal text-gray-400 ml-1 text-xs">· applies to all selected sheets</span>
                  )}
                </p>
                {(lo.rowFrom || lo.rowTo) && (
                  <button onClick={() => onRangeChange("", "")} className="text-sm text-gray-400 hover:text-black flex items-center gap-1">
                    <RotateCcw className="w-3 h-3" />All rows
                  </button>
                )}
              </div>
              <div className="flex gap-3">
                {[{ label: "From", val: lo.rowFrom, ph: "1" }, { label: "To", val: lo.rowTo, ph: sel.length === 1 && lo.sheetRowCount ? String(lo.sheetRowCount) : "last" }].map(({ label, val, ph }, i) => (
                  <div key={i} className="flex-1 space-y-1">
                    <p className="text-xs text-gray-500">{label} row</p>
                    <input type="number" min={1} placeholder={ph} value={val}
                      onChange={e => onRangeChange(i === 0 ? e.target.value : lo.rowFrom, i === 1 ? e.target.value : lo.rowTo)}
                      className="w-full px-3 py-2 text-sm rounded-lg border border-gray-200 bg-white focus:outline-none focus:ring-2 focus:ring-blue-500 text-black" />
                  </div>
                ))}
              </div>
            </div>

            {lo.error && <ErrorBox message={lo.error} />}

            <div className="flex gap-2">
              <button onClick={onConfirmSheet} disabled={lo.applyingSheet || noneSelected}
                className="flex-1 flex items-center justify-center gap-2 px-3 py-2.5 rounded-xl bg-black text-white text-sm font-semibold hover:bg-gray-800 disabled:opacity-50 transition-colors">
                {lo.applyingSheet
                  ? <><Spin />Parsing…</>
                  : <><ArrowRight className="w-3.5 h-3.5" />Use selected sheet{sel.length > 1 ? `s (${sel.length})` : ""}</>}
              </button>
              <button onClick={onAutoDetect} disabled={lo.applyingSheet}
                className="px-3 py-2.5 rounded-xl border border-gray-200 text-sm text-gray-500 hover:text-black hover:border-gray-400 disabled:opacity-50 transition-colors whitespace-nowrap">
                Auto-detect
              </button>
            </div>
          </div>
        );
      })()}
    </div>
  );
}

// ── DataFileRow ───────────────────────────────────────────────────────────────

function DataFileRow({ df, readyLayouts, onAssign, onTogglePreview, onProcess, onRemove }: {
  df: DataFile;
  readyLayouts: LayoutEntry[];
  onAssign: (layoutId: string) => void;
  onTogglePreview: () => void;
  onProcess: () => void;
  onRemove: () => void;
}) {
  const assignedLayout = readyLayouts.find(l => l.id === df.layoutId);
  const canProcess = !!assignedLayout && df.lineCount > 0 && !df.activated;

  return (
    <div className={`border rounded-xl overflow-hidden ${df.activated ? "border-emerald-200" : df.error ? "border-red-200" : "border-gray-200"}`}>
      {/* Main row */}
      <div className={`flex items-center gap-3 px-4 py-3 ${df.activated ? "bg-emerald-50" : "bg-white"}`}>
        {df.lineCount > 0
          ? <CheckCircle2 className="w-4 h-4 text-emerald-600 flex-shrink-0" />
          : df.error
          ? <AlertTriangle className="w-4 h-4 text-red-500 flex-shrink-0" />
          : <Spin />}

        <div className="flex-1 min-w-0">
          <p className="text-sm font-semibold text-black truncate">{df.fileName}</p>
          {df.lineCount > 0 && <p className="text-xs text-gray-500">{df.lineCount.toLocaleString()} records</p>}
          {df.error && <p className="text-xs text-red-600 truncate">{df.error}</p>}
        </div>

        {/* Layout assignment dropdown */}
        {df.lineCount > 0 && (
          <div className="relative flex-shrink-0">
            <select
              value={df.layoutId}
              onChange={e => onAssign(e.target.value)}
              className={`appearance-none text-xs font-medium px-2.5 py-1.5 pr-7 rounded-lg border cursor-pointer focus:outline-none focus:ring-2 focus:ring-blue-500 ${df.layoutId ? "border-blue-300 bg-blue-50 text-blue-800" : "border-gray-200 bg-white text-gray-500"}`}>
              <option value="">— assign layout —</option>
              {readyLayouts.map(lo => (
                <option key={lo.id} value={lo.id}>
                  {lo.result?.sheetName
                    ? `${lo.fileName} (${lo.result.sheetName}${lo.rowFrom || lo.rowTo ? ` r${lo.rowFrom || 1}–${lo.rowTo || "end"}` : ""})`
                    : `${lo.fileName} · ${lo.result!.fields.length}f`}
                </option>
              ))}
            </select>
            <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 text-gray-500 pointer-events-none" />
          </div>
        )}

        {/* Preview toggle */}
        {df.preview.length > 0 && (
          <button onClick={onTogglePreview}
            className="flex items-center gap-1 text-xs px-2 py-1.5 rounded-lg border border-gray-200 text-gray-500 hover:text-black hover:border-gray-400 transition-colors flex-shrink-0">
            <Eye className="w-3.5 h-3.5" />
            {df.showPreview ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
          </button>
        )}

        {/* Process button */}
        {canProcess && (
          <button onClick={onProcess}
            className="flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-lg bg-black text-white hover:bg-gray-800 transition-colors flex-shrink-0 whitespace-nowrap">
            <ArrowRight className="w-3.5 h-3.5" />Process
          </button>
        )}
        {df.activated && (
          <span className="text-xs font-semibold text-emerald-700 bg-emerald-100 px-2.5 py-1 rounded-lg flex-shrink-0 whitespace-nowrap">Active ↓</span>
        )}

        <button onClick={onRemove} className="text-gray-400 hover:text-black flex-shrink-0"><X className="w-4 h-4" /></button>
      </div>

      {/* Preview table (expandable) */}
      {df.showPreview && df.preview.length > 0 && assignedLayout?.result && (
        <div className="border-t border-gray-100 overflow-auto max-h-40">
          <table className="w-full text-xs border-collapse">
            <thead className="bg-gray-50 sticky top-0">
              <tr>
                {assignedLayout.result.fields.map(f => (
                  <th key={f.srlNo} className="px-2.5 py-1.5 text-left font-semibold text-gray-500 border-r border-gray-200 whitespace-nowrap">{f.varName}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {df.preview.map((row, ri) => (
                <tr key={ri} className="border-t border-gray-100 hover:bg-gray-50">
                  {row.map((cell, ci) => (
                    <td key={ci} className="px-2.5 py-1 font-mono border-r border-gray-100 whitespace-nowrap text-black">
                      {cell || <span className="text-gray-300 italic">—</span>}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ── Side-by-side compare modal ────────────────────────────────────────────────

function SideBySideModal({ loading, data, totalRows, leftLabel = "Original", rightLabel = "Anonymized", onClose }: {
  loading: boolean;
  data: { headers: string[]; original: string[][]; anonymized: string[][] } | null;
  totalRows: number;
  leftLabel?: string;
  rightLabel?: string;
  onClose: () => void;
}) {
  const [search, setSearch] = useState("");

  const filteredHeaders = data ? (search.trim() ? data.headers.filter(h => h.toLowerCase().includes(search.trim().toLowerCase())) : data.headers) : [];
  const filteredIdxs = data ? data.headers.map((h, i) => ({ h, i })).filter(({ h }) => !search.trim() || h.toLowerCase().includes(search.trim().toLowerCase())).map(({ i }) => i) : [];

  return (
    <div className="fixed inset-0 z-50 flex flex-col bg-white" style={{ fontFamily: "'Poppins', sans-serif" }}>
      <div className="flex items-center gap-4 px-6 py-4 border-b border-gray-200 bg-white flex-shrink-0">
        <div className="flex items-center gap-3 flex-1 min-w-0">
          <Columns2 className="w-5 h-5 text-emerald-600 flex-shrink-0" />
          <div>
            <h2 className="text-lg font-semibold text-black leading-tight">Original vs Anonymized</h2>
            <p className="text-sm text-gray-500">
              {data ? `Showing ${data.original.length.toLocaleString()} of ${totalRows.toLocaleString()} rows · ${data.headers.length} columns` : "Loading…"}
              {totalRows > 500 && data && <span className="ml-1 text-amber-600">(capped at 500 rows)</span>}
            </p>
          </div>
        </div>
        <div className="relative w-64 flex-shrink-0">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none" />
          <input type="text" value={search} onChange={e => setSearch(e.target.value)} placeholder="Filter columns…"
            className="w-full pl-9 pr-4 py-2 text-sm rounded-xl border border-gray-200 focus:outline-none focus:ring-2 focus:ring-emerald-500 text-black" />
        </div>
        <div className="flex items-center gap-2 flex-shrink-0 text-sm">
          <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gray-100 text-gray-600 font-medium"><span className="w-3 h-3 rounded-sm bg-amber-300 inline-block" />Changed</span>
          <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gray-100 text-gray-600 font-medium"><span className="w-3 h-3 rounded-sm bg-white border border-gray-300 inline-block" />Unchanged</span>
        </div>
        <button onClick={onClose} className="p-2 rounded-xl hover:bg-gray-100 text-gray-400 hover:text-black transition-colors flex-shrink-0"><X className="w-5 h-5" /></button>
      </div>

      {loading && (
        <div className="flex-1 flex items-center justify-center gap-3 text-gray-500">
          <Loader2 className="w-6 h-6 animate-spin text-emerald-500" />
          <span className="text-base font-medium">Building comparison…</span>
        </div>
      )}

      {!loading && data && (
        <div className="flex-1 flex min-h-0 divide-x divide-gray-200">
          {[{ label: leftLabel, rows: data.original, bg: "bg-gray-50", hBg: "bg-gray-50", hText: "text-gray-500" }, { label: rightLabel, rows: data.anonymized, bg: "bg-emerald-50", hBg: "bg-emerald-50/80 backdrop-blur-sm", hText: "text-emerald-700" }].map(({ label, rows, bg, hBg, hText }, side) => (
            <div key={side} className="flex-1 flex flex-col min-w-0">
              <div className={`px-4 py-2.5 ${bg} border-b border-gray-200 flex items-center gap-2 flex-shrink-0`}>
                <span className={`text-sm font-semibold ${side === 0 ? "text-black" : "text-emerald-800"}`}>{label}</span>
                <span className={`text-xs px-2 py-0.5 rounded-full ${side === 0 ? "bg-gray-200 text-gray-600" : "bg-emerald-100 text-emerald-700"}`}>{rows.length.toLocaleString()} rows</span>
              </div>
              <div className="flex-1 overflow-auto">
                <table className="text-xs border-collapse w-max min-w-full">
                  <thead className={`sticky top-0 ${hBg} z-10`}>
                    <tr>
                      <th className={`sticky left-0 ${side === 0 ? "bg-gray-50" : "bg-emerald-50"} px-3 py-2 text-left font-semibold ${hText} border-r border-b border-gray-200 whitespace-nowrap`}>#</th>
                      {filteredHeaders.map(h => <th key={h} className={`px-3 py-2 text-left font-semibold ${hText} border-r border-b border-gray-200 whitespace-nowrap`}>{h}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((row, ri) => (
                      <tr key={ri} className={ri % 2 === 0 ? "bg-white" : "bg-gray-50/50"}>
                        <td className="sticky left-0 px-3 py-1.5 text-gray-400 font-mono border-r border-gray-100 whitespace-nowrap" style={{ background: ri % 2 === 0 ? "white" : "rgb(249 250 251 / 0.5)" }}>{ri + 1}</td>
                        {filteredIdxs.map(ci => {
                          const origVal = data.original[ri]?.[ci] ?? "";
                          const anonVal = data.anonymized[ri]?.[ci] ?? "";
                          const changed = origVal !== anonVal;
                          return (
                            <td key={ci} className={`px-3 py-1.5 font-mono border-r border-gray-100 whitespace-nowrap ${changed ? (side === 0 ? "bg-amber-50 text-amber-900" : "bg-amber-100 text-amber-900 font-semibold") : ""}`}>
                              {row[ci] || <span className="text-gray-300">—</span>}
                            </td>
                          );
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── KeySettings ───────────────────────────────────────────────────────────────

function KeySettings({ keyMode, setKeyMode, seeds, setSeeds, passphrase, setPassphrase, pbkdf2Iter, setPbkdf2Iter, deterministic, setDeterministic, alphanumeric, setAlphanumeric, keyHexInput, setKeyHexInput }: {
  keyMode: "random" | "pbkdf2" | "hex"; setKeyMode: (m: "random" | "pbkdf2" | "hex") => void;
  seeds: number[]; setSeeds: (s: number[]) => void;
  passphrase: string; setPassphrase: (s: string) => void;
  pbkdf2Iter: number; setPbkdf2Iter: (n: number) => void;
  deterministic: boolean; setDeterministic: (b: boolean) => void;
  alphanumeric: boolean; setAlphanumeric: (b: boolean) => void;
  keyHexInput: string; setKeyHexInput: (s: string) => void;
}) {
  const setSeed = (i: number, val: number) => {
    const next = [...seeds];
    next[i] = val;
    setSeeds(next);
  };

  const SEED_LABELS = ["Seed 1", "Seed 2", "Seed 3", "Seed 4"];

  return (
    <div className="space-y-6 pt-4 border-t border-gray-100">
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
        {/* Key derivation mode */}
        <div className="space-y-3">
          <p className="text-sm font-semibold text-black flex items-center gap-2"><Key className="w-4 h-4" />Key derivation</p>
          <div className="space-y-2">
            {(["random", "pbkdf2", "hex"] as const).map(m => (
              <label key={m} className={`flex items-center gap-3 px-4 py-2.5 rounded-xl border cursor-pointer text-sm transition-colors ${keyMode === m ? "border-blue-500 bg-blue-50 text-black" : "border-gray-200 hover:border-blue-300 text-gray-500"}`}>
                <input type="radio" name="keymode" checked={keyMode === m} onChange={() => setKeyMode(m)} className="accent-blue-600" />
                {m === "random" ? "Random (4 seeds)" : m === "pbkdf2" ? "PBKDF2 passphrase" : "Paste hex key"}
              </label>
            ))}
          </div>
        </div>

        {/* Seed / passphrase / hex input */}
        <div className="space-y-3">
          <p className="text-sm font-semibold text-black">
            {keyMode === "random" ? "4 Encryption Seeds" : keyMode === "pbkdf2" ? "Passphrase" : "256-bit hex key"}
          </p>
          {keyMode === "pbkdf2" && (
            <div className="space-y-3">
              <input type="password" value={passphrase} onChange={e => setPassphrase(e.target.value)} placeholder="Enter passphrase…"
                className="w-full px-3 py-2.5 text-sm rounded-xl border border-gray-200 bg-white focus:outline-none focus:ring-2 focus:ring-blue-500 text-black" />
              <div>
                <p className="text-sm text-gray-500 mb-1">Iterations: {pbkdf2Iter.toLocaleString()}</p>
                <input type="range" min={10000} max={500000} step={10000} value={pbkdf2Iter} onChange={e => setPbkdf2Iter(Number(e.target.value))} className="w-full accent-blue-600" />
              </div>
            </div>
          )}
          {keyMode === "hex" && (
            <div className="space-y-2">
              <textarea value={keyHexInput} onChange={e => setKeyHexInput(e.target.value)} placeholder="Paste 64-char hex key…" rows={2}
                className={`w-full px-3 py-2.5 text-xs font-mono rounded-xl border bg-white focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none text-black ${keyHexInput && keyHexInput.trim().length !== 64 ? "border-red-400" : "border-gray-200"}`} />
              <p className={`text-sm ${keyHexInput.trim().length === 64 ? "text-emerald-600" : "text-gray-500"}`}>
                {keyHexInput.trim().length === 64 ? "✓ Valid 256-bit key" : `${keyHexInput.trim().length}/64 hex chars`}
              </p>
            </div>
          )}
          {keyMode === "random" && (
            <p className="text-xs text-gray-400">Same seeds → same keys (reproducible). Each seed generates an independent 256-bit key.</p>
          )}
        </div>

        {/* Deterministic + cipher info */}
        <div className="space-y-3">
          <label className={`flex items-start gap-3 px-4 py-3 rounded-xl border cursor-pointer text-sm transition-colors ${deterministic ? "border-blue-500 bg-blue-50 text-black" : "border-gray-200 hover:border-blue-300 text-gray-500"}`}>
            <input type="checkbox" checked={deterministic} onChange={e => setDeterministic(e.target.checked)} className="accent-blue-600 w-4 h-4 mt-0.5 flex-shrink-0" />
            <div>
              <p className="font-semibold">Deterministic mode</p>
              <p className="text-xs mt-1 opacity-70">{deterministic ? "Same value → same output." : "Each encrypted cell gets a distinct keystream; decrypt with the same file settings."}</p>
            </div>
          </label>
          <label className={`flex items-start gap-3 px-4 py-3 rounded-xl border cursor-pointer text-sm transition-colors ${alphanumeric ? "border-violet-500 bg-violet-50 text-black" : "border-gray-200 hover:border-violet-300 text-gray-500"}`}>
            <input type="checkbox" checked={alphanumeric} onChange={e => setAlphanumeric(e.target.checked)} className="accent-violet-600 w-4 h-4 mt-0.5 flex-shrink-0" />
            <div>
              <p className="font-semibold">Alphanumeric output</p>
              <p className="text-xs mt-1 opacity-70">{alphanumeric ? "Output uses 0–9 + a–z, same length as original." : "Output preserves original character class (digits stay digits, letters stay letters)."}</p>
            </div>
          </label>
          <div className="space-y-1 text-sm text-gray-500">
            {[["Cipher", "Custom FPE simulation"], ["Keys", "4 × 256-bit"], ["Rounds", "4-pass chain"], ["Stream", "xorshift128+"], ["Mode", deterministic ? "Deterministic" : "Per-cell"], ["Output", alphanumeric ? "Alphanumeric (0–9 a–z)" : "Preserves char class"]].map(([k, v]) => (
              <div key={k} className="flex gap-3"><span className="font-semibold text-black w-12 shrink-0">{k}</span><span>{v}</span></div>
            ))}
          </div>
        </div>
      </div>

      {/* 4 seed inputs — shown when keyMode === "random" */}
      {keyMode === "random" && (
        <div className="border border-blue-100 rounded-xl bg-blue-50/40 p-4 space-y-3">
          <div className="flex items-center gap-2 mb-1">
            <Key className="w-3.5 h-3.5 text-blue-600" />
            <p className="text-xs font-semibold text-blue-800 uppercase tracking-wide">4-Round Encryption Chain</p>
            <span className="text-xs text-blue-500 ml-1">Value jumps: original → round 1 → round 2 → round 3 → round 4 = encrypted</span>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {SEED_LABELS.map((label, i) => (
              <div key={i} className="space-y-1.5">
                <label className="text-xs font-semibold text-blue-700 flex items-center gap-1">
                  <span className="w-5 h-5 rounded-full bg-blue-600 text-white text-xs flex items-center justify-center font-bold flex-shrink-0">{i + 1}</span>
                  {label}
                </label>
                <input
                  type="number"
                  value={seeds[i] ?? 0}
                  onChange={e => setSeed(i, Number(e.target.value))}
                  className="w-full px-3 py-2 text-sm font-mono rounded-lg border border-blue-200 bg-white focus:outline-none focus:ring-2 focus:ring-blue-500 text-black"
                />
              </div>
            ))}
          </div>
          <p className="text-xs text-blue-600">
            Each seed derives an independent 256-bit key. The encrypted output differs from the original after every round — the final value is guaranteed to be different from the source.
          </p>
        </div>
      )}
    </div>
  );
}

// ── ColSelector ───────────────────────────────────────────────────────────────

function ColSelector({ allCols, selected, onChange, label }: { allCols: string[]; selected: Set<string>; onChange: (s: Set<string>) => void; label: string }) {
  const [query, setQuery] = useState("");
  const filtered = query.trim() ? allCols.filter(c => c.toLowerCase().includes(query.trim().toLowerCase())) : allCols;
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-sm font-semibold text-black">{label} <span className="font-normal text-gray-500">({selected.size}/{allCols.length})</span></span>
        <div className="flex gap-2">
          <button onClick={() => onChange(new Set(allCols))} className="text-sm px-3 py-1 rounded-lg border border-gray-200 hover:border-gray-400 text-gray-500 hover:text-black transition-colors">Select all</button>
          <button onClick={() => onChange(new Set())} className="text-sm px-3 py-1 rounded-lg border border-gray-200 hover:border-gray-400 text-gray-500 hover:text-black transition-colors">Clear</button>
        </div>
      </div>
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none" />
        <input type="text" value={query} onChange={e => setQuery(e.target.value)} placeholder="Search columns…"
          className="w-full pl-9 pr-4 py-2.5 text-sm rounded-xl border border-gray-200 bg-white focus:outline-none focus:ring-2 focus:ring-blue-500 text-black placeholder:text-gray-400" />
        {query && <button onClick={() => setQuery("")} className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-black"><X className="w-3.5 h-3.5" /></button>}
      </div>
      {filtered.length === 0 ? (
        <p className="text-sm text-gray-400 text-center py-4">No columns match "{query}"</p>
      ) : (
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 xl:grid-cols-5 gap-2 max-h-52 overflow-y-auto pr-1 pt-1">
          {filtered.map(col => (
            <label key={col} className={`flex items-center gap-2 px-3 py-2 rounded-xl border cursor-pointer text-sm transition-colors ${selected.has(col) ? "border-blue-500 bg-blue-50 text-black" : "border-gray-200 hover:border-blue-300 text-gray-500 hover:text-black"}`}>
              <input type="checkbox" checked={selected.has(col)} onChange={e => { const n = new Set(selected); if (e.target.checked) n.add(col); else n.delete(col); onChange(n); }} className="accent-blue-600 w-3.5 h-3.5 flex-shrink-0" />
              <span className="truncate font-mono text-xs">{col}</span>
            </label>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Small components ──────────────────────────────────────────────────────────

function ProgressBar({ pct, label, icon }: { pct: number; label: string; icon?: React.ReactNode }) {
  return (
    <div className="space-y-2">
      <div className="flex justify-between text-sm text-gray-500">
        <span className="flex items-center gap-2 min-w-0 truncate">{icon}{label}</span>
        <span className="flex-shrink-0 ml-2 font-semibold text-black">{pct}%</span>
      </div>
      <div className="h-2 rounded-full bg-gray-100 overflow-hidden">
        <div className="h-full bg-black rounded-full transition-all duration-200" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function StepBadge({ n, label, active, done }: { n: number; label: string; active: boolean; done: boolean }) {
  return (
    <div className={`flex items-center gap-2.5 text-base font-semibold ${active ? "text-black" : done ? "text-emerald-700" : "text-gray-400"}`}>
      <span className={`w-7 h-7 rounded-full flex items-center justify-center text-sm font-bold flex-shrink-0 ${active ? "bg-black text-white" : done ? "bg-emerald-500 text-white" : "bg-gray-100 text-gray-400"}`}>
        {done ? <CheckCircle2 className="w-4 h-4" /> : n}
      </span>
      {label}
    </div>
  );
}

function DropZone({ accept, multiple, icon, label, sublabel, inputRef, onFiles }: {
  accept: string; multiple?: boolean; icon: React.ReactNode; label: string; sublabel: string;
  inputRef: React.RefObject<HTMLInputElement | null>; onFiles: (files: File[]) => void;
}) {
  const [dragging, setDragging] = useState(false);
  return (
    <div className={`border-2 border-dashed rounded-2xl p-10 text-center cursor-pointer transition-all ${dragging ? "border-blue-500 bg-blue-50" : "border-gray-200 hover:border-blue-400 hover:bg-gray-50"}`}
      onDragOver={e => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={e => { e.preventDefault(); setDragging(false); const f = Array.from(e.dataTransfer.files); if (f.length) onFiles(f); }}
      onClick={() => inputRef.current?.click()}>
      <div className="flex flex-col items-center gap-4">
        <div className="flex items-center justify-center">{icon}</div>
        <div>
          <p className="text-base font-semibold text-black">{label}</p>
          <p className="text-sm text-gray-500 mt-1">{sublabel}</p>
        </div>
        <span className="text-sm px-4 py-2 rounded-xl border border-gray-200 bg-white text-gray-500 font-medium">Browse</span>
      </div>
    </div>
  );
}

function SuccessBadge({ text }: { text: string }) {
  return (
    <div className="flex items-center gap-2.5 text-sm text-emerald-700 bg-emerald-50 border border-emerald-200 rounded-xl px-4 py-2.5 font-medium">
      <CheckCircle2 className="w-4 h-4 flex-shrink-0" /><span>{text}</span>
    </div>
  );
}

function InfoBadge({ icon, text }: { icon: React.ReactNode; text: string }) {
  return (
    <div className="flex items-center gap-2.5 text-sm text-blue-700 bg-blue-50 border border-blue-200 rounded-xl px-4 py-2.5 font-medium">
      {icon}<span>{text}</span>
    </div>
  );
}

function ErrorBox({ message }: { message: string }) {
  return (
    <div className="flex items-start gap-2.5 text-sm text-red-700 bg-red-50 border border-red-200 rounded-xl px-4 py-2.5 font-medium">
      <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />{message}
    </div>
  );
}

function Spin() {
  return <div className="w-4 h-4 border-2 border-current/30 border-t-current rounded-full animate-spin flex-shrink-0" />;
}
