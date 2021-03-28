

const fs = require('fs')

console.log("Hello World");


var factory = require('../build_emcc/app/app.js');

factory().then((instance) => {
    // instance._sayHi(); // direct calling works
    // instance.ccall("sayHi"); // using ccall etc. also work
    // console.log(instance._daysInWeek()); // values can be returned, etc.

    var elf_analysis_analyse_data = instance.cwrap('elf_analysis_analyse_data', 'number', ['number', 'number']);
    var elf_analysis_get_filename = instance.cwrap('elf_analysis_get_filename', 'string');
    var elf_analysis_get_lines_size = instance.cwrap('elf_analysis_get_lines_size', 'number');

    var elf_analysis_get_address = instance.cwrap('elf_analysis_get_address', 'number', ['number']);
    var elf_analysis_get_opcode_description = instance.cwrap('elf_analysis_get_opcode_description', 'string', ['number']);
    var elf_analysis_get_branch_destination = instance.cwrap('elf_analysis_get_branch_destination', 'string', ['number']);

    var elf_analysis_get_line_filename = instance.cwrap('elf_analysis_get_line_filename', 'string', ['number']);
    var elf_analysis_get_line_path = instance.cwrap('elf_analysis_get_line_path', 'string', ['number']);
    var elf_analysis_get_line_line = instance.cwrap('elf_analysis_get_line_line', 'number', ['number']);
    var elf_analysis_get_line_column = instance.cwrap('elf_analysis_get_line_column', 'number', ['number']);
    var elf_analysis_get_line_isStartSequence = instance.cwrap('elf_analysis_get_line_isStartSequence', 'number', ['number']);

    var elf_analysis_get_branch_destination_line_filename = instance.cwrap('elf_analysis_get_branch_destination_line_filename', 'string', ['number']);
    var elf_analysis_get_branch_destination_line_path = instance.cwrap('elf_analysis_get_branch_destination_line_path', 'string', ['number']);
    var elf_analysis_get_branch_destination_line_line = instance.cwrap('elf_analysis_get_branch_destination_line_line', 'number', ['number']);
    var elf_analysis_get_branch_destination_line_column = instance.cwrap('elf_analysis_get_branch_destination_line_column', 'number', ['number']);
    var elf_analysis_get_branch_destination_line_isStartSequence = instance.cwrap('elf_analysis_get_branch_destination_line_isStartSequence', 'number', ['number']);



    // var table_size = instance.cwrap('table_size', 'number');
    // var get_source_line = instance.cwrap('get_source_line', 'string', ['number']);
    // var get_target_line = instance.cwrap('get_target_line', 'string', ['number']);

    const file = './test/ZEUS_STM32F765NG.elf';

    try {
        const data = fs.readFileSync(file, null);

        console.log("Number of Lines: ", elf_analysis_get_lines_size());

        // Allocate some space in the heap for the data (making sure to use the appropriate memory size of the elements)
        buffer = instance._malloc(data.length)
        // Assign the data to the heap - Keep in mind bytes per element
        instance.HEAPU8.set(data, buffer);

        var ret = elf_analysis_analyse_data(buffer, data.length);
        console.log("Number of Lines: ", elf_analysis_get_lines_size());
    } catch (err) {
        console.error(err)
    }

    // fs.readFile(file, null , (err, data) => {
    //     if (err) {
    //       console.error(err)
    //       return
    //     }

        
        
        // var ret = read_file('./working/test/NucleoProject.elf')
        // var filename = readerEvt.target.fileName
        // FS.mkdir('/working');
        // var stream = FS.open('working/elf_file.elf', 'w+');
        // FS.write(stream, data, 0, data.length, 0);
        // FS.close(stream);
        // Module['FS_createDataFile']('/', file, data, true, true, true);
        

        

        // console.log(data)
    //   })

    // var fr = new FileReader();
    // reader.fileName = file
    // fr.onload = function (readerEvt) {
    //     var data = new Uint8Array(fr.result);

    //     console.log("Number of Lines: ", elf_analysis_get_lines_size());
    //     // var ret = read_file('./working/test/NucleoProject.elf')
    //     var filename = readerEvt.target.fileName
    //     Module['FS_createDataFile']('/', filename, data, true, true, true);
    //     var ret = elf_analysis_read_file(filename)
    //     console.log("Number of Lines: ", elf_analysis_get_lines_size());

    //     fileInput.value = '';
    // }
    
    
    // fr.readAsArrayBuffer(file);



    // var array = []; // empty array

    // var size = table_size();
    // for(i = 0; i < size; ++i) {
    //     array.push({ source_line: get_source_line(i), target_line: get_target_line(i) });
    // }

    // for (var i = 0; i < array.length; i++) {
    //     console.log(array[i].source_line);
    //     console.log(array[i].target_line);
    //     console.log(" ");
    //   }


  });



