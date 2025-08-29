// CWE: CWE-1300
module insecure_storage(clk, rst, data_in, key, data_out);
    input wire clk;
    input wire rst;
    input wire [127:0] data_in;
    input wire [127:0] key;
    output reg [127:0] data_out;

    reg [127:0] internal_data;
    reg [127:0] internal_key; // Key stored directly in a register

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            internal_data <= 128'b0;
            internal_key <= 128'b0; // Key reset to zero
        end else begin
            internal_data <= data_in ^ internal_key; // Simple XOR with key
            internal_key <= key; // Key directly assigned
        end
    end

    always @(posedge clk) begin
        data_out <= internal_data; // Output the processed data
    end
endmodule