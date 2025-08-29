// CWE: CWE-226
module secure_memory (
    input wire clk,
    input wire rst,
    input wire write_enable,
    input wire [7:0] data_in,
    output reg [7:0] data_out
);

    reg [7:0] memory [0:3];
    reg [1:0] address;

    always @(posedge clk) begin
        if (rst) begin
            address <= 2'b00;
            // Intentionally not clearing memory to demonstrate CWE-226
        end else if (write_enable) begin
            memory[address] <= data_in;
            address <= address + 1;
        end
    end

    always @(posedge clk) begin
        if (!write_enable) begin
            data_out <= memory[address];
        end
    end

endmodule