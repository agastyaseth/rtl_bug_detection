// CWE: CWE-1244
module secure_storage(clk, rst, write_enable, address, data_in, data_out, debug_access);
    input wire clk;
    input wire rst;
    input wire write_enable;
    input wire [7:0] address;
    input wire [31:0] data_in;
    output wire [31:0] data_out;
    output wire [31:0] debug_access; // Debug access to internal data

    reg [31:0] memory [255:0];
    reg [31:0] internal_data;

    always @(posedge clk) begin
        if (rst) begin
            internal_data <= 32'b0;
        end else if (write_enable) begin
            memory[address] <= data_in;
            internal_data <= data_in;
        end
    end

    assign data_out = memory[address];
    assign debug_access = internal_data; // Exposing internal data for debugging

endmodule