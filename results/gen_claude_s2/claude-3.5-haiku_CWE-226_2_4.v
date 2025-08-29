// CWE: CWE-226
module secure_register_file (
    input wire clk,
    input wire rst,
    input wire [3:0] write_addr,
    input wire [31:0] write_data,
    input wire write_enable,
    input wire [3:0] read_addr,
    output reg [31:0] read_data
);

    reg [31:0] registers [15:0];
    reg [3:0] last_write_addr;

    always @(posedge clk) begin
        if (rst) begin
            // Sensitive: Not clearing previous register contents
            last_write_addr <= 4'b0;
        end else begin
            if (write_enable) begin
                registers[write_addr] <= write_data;
                last_write_addr <= write_addr;
            end

            // Potential vulnerability: Reading without clearing previous contents
            read_data <= registers[read_addr];
        end
    end

endmodule