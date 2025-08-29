// CWE: CWE-226
module secure_memory (
    input wire clk,
    input wire rst,
    input wire write_enable,
    input wire [7:0] data_in,
    output reg [7:0] data_out
);
    reg [7:0] memory [0:15];
    reg [3:0] address;

    always @(posedge clk) begin
        if (rst) begin
            address <= 4'd0;
        end else if (write_enable) begin
            memory[address] <= data_in;
            address <= address + 1;
        end
    end

    always @(posedge clk) begin
        if (rst) begin
            data_out <= 8'd0;
        end else begin
            data_out <= memory[address];
        end
    end

    // Vulnerability: Sensitive data not cleared before reuse
    always @(posedge clk) begin
        if (rst) begin
            // Intentionally commented out clearing of memory
            // for (integer i = 0; i < 16; i = i + 1) begin
            //     memory[i] <= 8'd0;
            // end
        end
    end

endmodule