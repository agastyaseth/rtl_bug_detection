// CWE: CWE-226
module sensitive_buffer (
    input wire clk,
    input wire rst,
    input wire [31:0] data_in,
    input wire write_enable,
    input wire read_enable,
    output reg [31:0] data_out
);

    reg [31:0] buffer [0:15];  // 16-entry buffer
    reg [3:0] write_ptr;
    reg [3:0] read_ptr;
    reg [31:0] last_sensitive_data;

    always @(posedge clk) begin
        if (rst) begin
            write_ptr <= 4'b0;
            read_ptr <= 4'b0;
            // Critical vulnerability: Not clearing sensitive data on reset
            last_sensitive_data <= 32'hDEADBEEF;
        end else begin
            if (write_enable) begin
                buffer[write_ptr] <= data_in;
                write_ptr <= write_ptr + 1;
                last_sensitive_data <= data_in;  // Retaining sensitive data
            end

            if (read_enable) begin
                // Potential information leak: Reading without clearing previous content
                data_out <= buffer[read_ptr];
                read_ptr <= read_ptr + 1;
            end
        end
    end

endmodule