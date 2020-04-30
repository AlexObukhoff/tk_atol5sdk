import qbs 1.0
import "../qbs/libTemplate.qbs" as ThirdpartyLib

ThirdpartyLib {
	name: "ATOL5"

	Depends { name: "Qt"; submodules: ["gui", "axcontainer"] }

	files: [
		"wrappers/cpp/fptr10/*.*"
	]

	cpp.includePaths: product.sourceDirectory + "/.."
	
	Export {
		Depends { name: "cpp" }
		cpp.includePaths: [	product.sourceDirectory + "/atol5/include" ]
		cpp.libraryPaths: [
			product.sourceDirectory + "/atol5/bin",
			product.sourceDirectory + "/atol5/nt-x86-msvc2015" ]
	}
}

