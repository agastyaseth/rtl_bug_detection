// CWE: CWE-1244
module secure_processor(clk, rst, cmd, data_in, data_out, debug_data);
    input wire clk;
    input wire rst;
    input wire [3:0] cmd;
    input wire [31:0] data_in;
    output reg [31:0] data_out;
    output wire [31:0] debug_data;

    reg [31:0] internal_reg;
    reg [31:0] secret_key;
    reg [31:0] temp_reg;

    // Exposing internal register for debugging purposes
    assign debug_data = internal_reg;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            internal_reg <= 32'h0;
            secret_key <= 32'hDEADBEEF;
            temp_reg <= 32'h0;
        end else begin
            case (cmd)
                4'b0001: internal_reg <= data_in;
                4'b0010: data_out <= internal_reg;
                4'b0011: temp_reg <= internal_reg ^ secret_key;
                4'b0100: data_out <= temp_reg;
                default: data_out <= 32'h0;
            endcase
        end
    end

endmodule