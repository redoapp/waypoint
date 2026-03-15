package covreport

import (
	"embed"
	"fmt"
	"html"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/cover"
)

//go:embed template.html
var templateFS embed.FS

// CoverageType identifies which test type(s) cover a block.
type CoverageType int

const (
	Uncovered CoverageType = iota
	Unit
	Integration
	Both
)

// LineCoverage holds the coverage info for a single source line.
type LineCoverage struct {
	Class string        // CSS class
	Title string        // hover tooltip
	Text  template.HTML // syntax-highlighted HTML
}

// FileReport holds per-file coverage data for the report.
type FileReport struct {
	ID       string // HTML-safe id
	Name     string // source file path
	TotalPct string // coverage percentage
	Lines    []LineCoverage
}

// DirReport holds per-directory coverage summary.
type DirReport struct {
	ID       string
	Name     string
	Children []DirChild
}

// DirChild is one row in a directory summary table.
type DirChild struct {
	ID           string
	Name         string
	TotalStmts   int
	CoveredStmts int
	Pct          string
}

// SummaryRow holds one row of the summary table.
type SummaryRow struct {
	Name         string
	TotalStmts   int
	CoveredStmts int
	Pct          string
}

type reportData struct {
	Files       []FileReport
	Dirs        []DirReport
	SidebarHTML template.HTML
	Summary     []SummaryRow
}

// blockKey identifies a coverage block by position.
type blockKey struct {
	StartLine, StartCol, EndLine, EndCol int
}

type blockInfo struct {
	NumStmt int
	Counts  map[string]int // profile name -> count
}

// Generate reads named coverage profiles and writes an HTML report.
// profiles maps profile names (e.g. "unit", "integration") to file paths.
func Generate(w io.Writer, profiles map[string]string) error {
	// Parse all profiles.
	allProfiles := make(map[string][]*cover.Profile, len(profiles))
	for name, path := range profiles {
		p, err := cover.ParseProfiles(path)
		if err != nil {
			return fmt.Errorf("parsing %s profile %s: %w", name, path, err)
		}
		allProfiles[name] = p
	}

	return GenerateFromParsed(w, allProfiles)
}

// GenerateFromParsed generates a report from already-parsed profiles.
func GenerateFromParsed(w io.Writer, allProfiles map[string][]*cover.Profile) error {
	// Collect all files and their blocks across profiles.
	type fileBlocks struct {
		blocks map[blockKey]*blockInfo
	}
	fileMap := make(map[string]*fileBlocks)

	for name, profiles := range allProfiles {
		for _, p := range profiles {
			fb, ok := fileMap[p.FileName]
			if !ok {
				fb = &fileBlocks{blocks: make(map[blockKey]*blockInfo)}
				fileMap[p.FileName] = fb
			}
			for _, b := range p.Blocks {
				key := blockKey{b.StartLine, b.StartCol, b.EndLine, b.EndCol}
				bi, ok := fb.blocks[key]
				if !ok {
					bi = &blockInfo{NumStmt: b.NumStmt, Counts: make(map[string]int)}
					fb.blocks[key] = bi
				}
				bi.Counts[name] += b.Count
			}
		}
	}

	// Sort file names.
	fileNames := make([]string, 0, len(fileMap))
	for name := range fileMap {
		fileNames = append(fileNames, name)
	}
	sort.Strings(fileNames)

	// Build summary per profile name + total.
	profileNames := make([]string, 0, len(allProfiles))
	for name := range allProfiles {
		profileNames = append(profileNames, name)
	}
	sort.Strings(profileNames)

	summaryByName := make(map[string][2]int) // name -> [total, covered]
	var totalStmts, totalCovered int

	// Build file reports.
	var fileReports []FileReport
	for _, fileName := range fileNames {
		fb := fileMap[fileName]

		// Read source file.
		src, err := readSource(fileName)
		if err != nil {
			// Skip files we can't read.
			continue
		}

		// Syntax-highlight source into per-line HTML.
		highlightedLines := highlightGoSource(src)

		// Build per-line coverage by finding the "best" block covering each line.
		lineCov := make([]CoverageType, len(highlightedLines))
		lineTitles := make([]string, len(highlightedLines))
		for i := range lineCov {
			lineCov[i] = -1 // unset, means not in any block
		}

		// First pass: compute summaries from blocks.
		for _, bi := range fb.blocks {
			covType := classifyBlock(bi.Counts)

			// Per-profile summary: count stmts for each profile that has the block.
			for name, count := range bi.Counts {
				s := summaryByName[name]
				s[0] += bi.NumStmt
				if count > 0 {
					s[1] += bi.NumStmt
				}
				summaryByName[name] = s
			}
			totalStmts += bi.NumStmt
			if covType != Uncovered {
				totalCovered += bi.NumStmt
			}
		}

		// Second pass: build per-line coverage.
		for key, bi := range fb.blocks {
			covType := classifyBlock(bi.Counts)
			title := blockTitle(bi.Counts)
			for line := key.StartLine; line <= key.EndLine && line <= len(highlightedLines); line++ {
				idx := line - 1
				// Prefer higher coverage type (Both > Unit/Integration > Uncovered).
				if covType > lineCov[idx] {
					lineCov[idx] = covType
					lineTitles[idx] = title
				}
			}
		}

		// Build line coverage entries.
		var fileStmts, fileCovered int
		lineEntries := make([]LineCoverage, len(highlightedLines))
		for i, lineHTML := range highlightedLines {
			ct := lineCov[i]
			cls := ""
			title := lineTitles[i]
			switch ct {
			case Uncovered:
				cls = "cov-none"
			case Unit:
				cls = "cov-unit"
			case Integration:
				cls = "cov-integration"
			case Both:
				cls = "cov-both"
			default:
				// Line not in any coverage block — no class.
			}
			lineEntries[i] = LineCoverage{
				Class: cls,
				Title: title,
				Text:  lineHTML,
			}
		}

		// Compute file-level stats from blocks (not lines).
		for _, bi := range fb.blocks {
			fileStmts += bi.NumStmt
			if classifyBlock(bi.Counts) != Uncovered {
				fileCovered += bi.NumStmt
			}
		}

		pct := "0.0"
		if fileStmts > 0 {
			pct = fmt.Sprintf("%.1f", float64(fileCovered)/float64(fileStmts)*100)
		}

		fileReports = append(fileReports, FileReport{
			ID:       fileID(fileName),
			Name:     fileName,
			TotalPct: pct,
			Lines:    lineEntries,
		})
	}

	// Build per-file stats map for directory aggregation.
	fileStatsMap := make(map[string]fileStats)
	for _, fr := range fileReports {
		fb := fileMap[fr.Name]
		var s, c int
		for _, bi := range fb.blocks {
			s += bi.NumStmt
			if classifyBlock(bi.Counts) != Uncovered {
				c += bi.NumStmt
			}
		}
		fileStatsMap[fr.Name] = fileStats{s, c}
	}

	// Build directory summaries by grouping files into their parent dir.
	dirStatsMap := make(map[string]fileStats) // dir path -> aggregated stats
	dirFiles := make(map[string][]string)     // dir path -> child file names
	for _, fr := range fileReports {
		dir := dirOf(fr.Name)
		fs := fileStatsMap[fr.Name]
		ds := dirStatsMap[dir]
		ds.stmts += fs.stmts
		ds.covered += fs.covered
		dirStatsMap[dir] = ds
		dirFiles[dir] = append(dirFiles[dir], fr.Name)
	}

	// Propagate stats up to parent directories.
	allDirs := make(map[string]bool)
	for dir := range dirStatsMap {
		for d := dir; d != "" && d != "."; d = dirOf(d) {
			allDirs[d] = true
		}
	}
	// Recompute each dir by summing all leaf dirs that are descendants.
	for dir := range allDirs {
		if _, ok := dirStatsMap[dir]; ok {
			continue // already has direct files
		}
		dirStatsMap[dir] = fileStats{}
	}
	// Walk all dirs and accumulate into ancestors.
	parentDirStats := make(map[string]fileStats)
	for dir, fs := range dirStatsMap {
		for d := dir; d != "" && d != "."; d = dirOf(d) {
			s := parentDirStats[d]
			s.stmts += fs.stmts
			s.covered += fs.covered
			parentDirStats[d] = s
		}
		// Also include root if files are at root.
	}
	// Merge: parentDirStats has the roll-up, dirStatsMap has leaf-level.
	// Use parentDirStats for display since it includes children.
	for d, fs := range parentDirStats {
		dirStatsMap[d] = fs
	}

	// Build DirReport for each directory.
	sortedDirs := make([]string, 0, len(allDirs))
	for d := range allDirs {
		sortedDirs = append(sortedDirs, d)
	}
	sort.Strings(sortedDirs)

	var dirReports []DirReport
	for _, dir := range sortedDirs {
		dr := DirReport{
			ID:   dirID(dir),
			Name: dir,
		}

		// Add subdirectory children.
		for _, d2 := range sortedDirs {
			if dirOf(d2) == dir && d2 != dir {
				ds := dirStatsMap[d2]
				dr.Children = append(dr.Children, DirChild{
					ID:           dirID(d2),
					Name:         baseOf(d2) + "/",
					TotalStmts:   ds.stmts,
					CoveredStmts: ds.covered,
					Pct:          pctStr(ds.covered, ds.stmts),
				})
			}
		}

		// Add file children.
		for _, fn := range dirFiles[dir] {
			fs := fileStatsMap[fn]
			dr.Children = append(dr.Children, DirChild{
				ID:           fileID(fn),
				Name:         baseOf(fn),
				TotalStmts:   fs.stmts,
				CoveredStmts: fs.covered,
				Pct:          pctStr(fs.covered, fs.stmts),
			})
		}

		dirReports = append(dirReports, dr)
	}

	// Build sidebar tree HTML.
	sidebarHTML := renderSidebarHTML(fileReports, fileStatsMap, dirStatsMap, sortedDirs, dirFiles)

	// Build summary rows.
	var summaryRows []SummaryRow
	for _, name := range profileNames {
		s := summaryByName[name]
		summaryRows = append(summaryRows, SummaryRow{
			Name:         name,
			TotalStmts:   s[0],
			CoveredStmts: s[1],
			Pct:          pctStr(s[1], s[0]),
		})
	}
	summaryRows = append(summaryRows, SummaryRow{
		Name:         "Total",
		TotalStmts:   totalStmts,
		CoveredStmts: totalCovered,
		Pct:          pctStr(totalCovered, totalStmts),
	})

	// Render template.
	tmpl, err := template.ParseFS(templateFS, "template.html")
	if err != nil {
		return fmt.Errorf("parsing template: %w", err)
	}

	return tmpl.Execute(w, reportData{
		Files:       fileReports,
		Dirs:        dirReports,
		SidebarHTML: sidebarHTML,
		Summary:     summaryRows,
	})
}

func classifyBlock(counts map[string]int) CoverageType {
	covered := 0
	var lastName string
	for name, count := range counts {
		if count > 0 {
			covered++
			lastName = name
		}
	}
	switch {
	case covered == 0:
		return Uncovered
	case covered > 1:
		return Both
	case lastName == "unit":
		return Unit
	case lastName == "integration":
		return Integration
	default:
		// Single profile with non-standard name; treat as unit.
		return Unit
	}
}

func blockTitle(counts map[string]int) string {
	var parts []string
	for name, count := range counts {
		if count > 0 {
			parts = append(parts, fmt.Sprintf("%s: %dx", name, count))
		}
	}
	if len(parts) == 0 {
		return "not covered"
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

func fileID(name string) string {
	r := strings.NewReplacer("/", "-", ".", "-")
	return "file-" + r.Replace(name)
}

func dirID(name string) string {
	r := strings.NewReplacer("/", "-", ".", "-")
	return "dir-" + r.Replace(name)
}

func dirOf(name string) string {
	idx := strings.LastIndex(name, "/")
	if idx < 0 {
		return ""
	}
	return name[:idx]
}

func baseOf(name string) string {
	idx := strings.LastIndex(name, "/")
	if idx < 0 {
		return name
	}
	return name[idx+1:]
}

func pctStr(covered, total int) string {
	if total == 0 {
		return "0.0"
	}
	return fmt.Sprintf("%.1f", float64(covered)/float64(total)*100)
}

type fileStats struct {
	stmts, covered int
}

func renderSidebarHTML(
	fileReports []FileReport,
	fileStatsMap map[string]fileStats,
	dirStatsMap map[string]fileStats,
	sortedDirs []string,
	dirFiles map[string][]string,
) template.HTML {
	// Build a map of dir -> direct child dirs.
	childDirs := make(map[string][]string)
	for _, d := range sortedDirs {
		parent := dirOf(d)
		childDirs[parent] = append(childDirs[parent], d)
	}

	// Find the top-level dirs (whose parent is not in sortedDirs set).
	dirSet := make(map[string]bool, len(sortedDirs))
	for _, d := range sortedDirs {
		dirSet[d] = true
	}
	var topDirs []string
	for _, d := range sortedDirs {
		parent := dirOf(d)
		if !dirSet[parent] {
			topDirs = append(topDirs, d)
		}
	}

	var buf strings.Builder
	buf.WriteString("<ul>")
	for _, d := range topDirs {
		renderTreeNode(&buf, d, 0, childDirs, dirStatsMap, dirFiles, fileStatsMap)
	}
	buf.WriteString("</ul>")
	return template.HTML(buf.String())
}

func renderTreeNode(
	buf *strings.Builder,
	dir string,
	depth int,
	childDirs map[string][]string,
	dirStatsMap map[string]fileStats,
	dirFiles map[string][]string,
	fileStatsMap map[string]fileStats,
) {
	ds := dirStatsMap[dir]
	id := dirID(dir)
	label := html.EscapeString(baseOf(dir))
	pct := pctStr(ds.covered, ds.stmts)
	pad := fmt.Sprintf("padding-left:%dem", depth)

	buf.WriteString("<li>")
	fmt.Fprintf(buf, `<div class="tree-item" data-target="%s" onclick="showSection('%s')" style="%s">`, id, id, pad)
	fmt.Fprintf(buf, `<span class="tree-toggle" onclick="toggleChildren(event, '%s')">&#9658;</span>`, id)
	fmt.Fprintf(buf, `<span class="tree-label">%s/</span>`, label)
	fmt.Fprintf(buf, `<span class="pct">%s%%</span>`, pct)
	buf.WriteString("</div>")

	fmt.Fprintf(buf, `<ul class="children" id="children-%s">`, id)

	// Subdirectories.
	for _, cd := range childDirs[dir] {
		renderTreeNode(buf, cd, depth+1, childDirs, dirStatsMap, dirFiles, fileStatsMap)
	}

	// Files.
	for _, fn := range dirFiles[dir] {
		fs := fileStatsMap[fn]
		fid := fileID(fn)
		flabel := html.EscapeString(baseOf(fn))
		fpct := pctStr(fs.covered, fs.stmts)
		fpad := fmt.Sprintf("padding-left:%dem", depth+1)

		buf.WriteString("<li>")
		fmt.Fprintf(buf, `<div class="tree-item" data-target="%s" onclick="showSection('%s')" style="%s">`, fid, fid, fpad)
		buf.WriteString(`<span class="tree-toggle"></span>`)
		fmt.Fprintf(buf, `<span class="tree-label">%s</span>`, flabel)
		fmt.Fprintf(buf, `<span class="pct">%s%%</span>`, fpct)
		buf.WriteString("</div></li>")
	}

	buf.WriteString("</ul></li>")
}

// readSource reads a Go source file, resolving the package path.
func readSource(name string) ([]byte, error) {
	// Try as-is first (may be a relative or absolute path).
	if data, err := os.ReadFile(name); err == nil {
		return data, nil
	}

	// Coverage profiles use import paths like "github.com/foo/bar/pkg/file.go".
	// Try to find it via GOPATH or module cache.
	if gopath := os.Getenv("GOPATH"); gopath != "" {
		p := filepath.Join(gopath, "src", name)
		if data, err := os.ReadFile(p); err == nil {
			return data, nil
		}
	}

	// Try relative to current directory by stripping the module prefix.
	// This works when running from the module root.
	if idx := strings.Index(name, "/"); idx >= 0 {
		// Try progressively shorter prefixes.
		parts := strings.Split(name, "/")
		for i := 1; i < len(parts); i++ {
			candidate := strings.Join(parts[i:], "/")
			if data, err := os.ReadFile(candidate); err == nil {
				return data, nil
			}
		}
	}

	return nil, fmt.Errorf("cannot find source for %s", name)
}
