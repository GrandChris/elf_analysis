


console.log("Hello World");


var factory = require('../build_emcc/app/app.js');

factory().then((instance) => {
    // instance._sayHi(); // direct calling works
    // instance.ccall("sayHi"); // using ccall etc. also work
    // console.log(instance._daysInWeek()); // values can be returned, etc.

    var read_file = instance.cwrap('read_file', 'number', ['string']);
    var get_filename = instance.cwrap('get_filename', 'string');
    var get_lines_size = instance.cwrap('get_lines_size', 'number');

    var get_address = instance.cwrap('get_address', 'number', ['number']);
    var get_opcode_description = instance.cwrap('get_opcode_description', 'string', ['number']);
    var get_branch_destination = instance.cwrap('get_branch_destination', 'string', ['number']);

    var get_line_filename = instance.cwrap('get_line_filename', 'string', ['number']);
    var get_line_path = instance.cwrap('get_line_path', 'string', ['number']);
    var get_line_line = instance.cwrap('get_line_line', 'number', ['number']);
    var get_line_column = instance.cwrap('get_line_column', 'number', ['number']);
    var get_line_isEndSequence = instance.cwrap('get_line_isEndSequence', 'number', ['number']);

    var get_branch_destination_line_filename = instance.cwrap('get_branch_destination_line_filename', 'string', ['number']);
    var get_branch_destination_line_path = instance.cwrap('get_branch_destination_line_path', 'string', ['number']);
    var get_branch_destination_line_line = instance.cwrap('get_branch_destination_line_line', 'number', ['number']);
    var get_branch_destination_line_column = instance.cwrap('get_branch_destination_line_column', 'number', ['number']);
    var get_branch_destination_line_isEndSequence = instance.cwrap('get_branch_destination_line_isEndSequence', 'number', ['number']);



    // var table_size = instance.cwrap('table_size', 'number');
    // var get_source_line = instance.cwrap('get_source_line', 'string', ['number']);
    // var get_target_line = instance.cwrap('get_target_line', 'string', ['number']);


    console.log("Number of Lines: ", get_lines_size());
    // var ret = read_file('./working/test/NucleoProject.elf')
    var ret = read_file('./working/test/ZEUS_STM32F765NG.elf')
    console.log("Number of Lines: ", get_lines_size());

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



