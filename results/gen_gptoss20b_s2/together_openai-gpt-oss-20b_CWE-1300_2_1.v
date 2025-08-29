// CWE: CWE-1300
module example_module(
    input  wire        clk,
    input  wire        rst,
    input  wire        start,
    input  wire [31:0] data_in,
    input  wire [31:0] key_in,
    output reg  [31:0] data_out,
    output reg         valid
);
    // Internal registers
    reg  [31:0] key_reg;
    reg  [1:0]  state; // 0: idle, 1: load key, 2: encrypt, 3: output valid

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            state   <= 2'b00;
            key_reg <= 32'b0;
            data_out <= 32'b0;
            valid <= 1'b0;
        end else begin
            case (state)
                2'b00: begin // idle
                    valid <= 1'b0;
                    if (start) state <= 2'b01;
                end
                2'b01: begin // load key
                    key_reg <= key_in;
                    state <= 2'b10;
                end
                2'b10: begin // encrypt
                    data_out <= data_in ^ key_reg;
                    state <= 2'b11;
                end
                2'b11: begin // output valid
                    valid <= 1'b1;
                    state <= 2'b00;
                end
                default: state <= 2'b00;
            endcase
        end
    end
endmodule