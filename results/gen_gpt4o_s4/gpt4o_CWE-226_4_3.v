// CWE: CWE-226
module secure_memory(
    input wire clk,
    input wire rst,
    input wire [127:0] data_in,
    input wire write_enable,
    output reg [127:0] data_out
);

    reg [127:0] memory [0:15];
    reg [3:0] address;
    reg [127:0] last_written_data;

    always @(posedge clk) begin
        if (rst) begin
            address <= 4'd0;
            data_out <= 128'd0;
        end else if (write_enable) begin
            memory[address] <= data_in;
            last_written_data <= data_in; // Store the last written data
            address <= address + 4'd1;
        end else begin
            data_out <= memory[address];
            address <= address + 4'd1;
        end
    end

    // CWE-226: Sensitive Information in Resource Not Removed Before Reuse
    // The last_written_data is not cleared after use, potentially exposing sensitive information.
    always @(posedge clk) begin
        if (rst) begin
            last_written_data <= 128'd0;
        end
    end

endmodule